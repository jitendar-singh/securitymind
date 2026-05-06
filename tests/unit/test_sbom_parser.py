import json

import pytest

from secmind.sub_agents.vuln_triage_agent.sbom_parser import SBOMParser, parse_sbom


CYCLONEDX_MINIMAL = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [
        {
            "name": "requests",
            "version": "2.31.0",
            "licenses": [{"license": {"id": "Apache-2.0"}}],
            "purl": "pkg:pypi/requests@2.31.0",
        },
        {
            "name": "flask",
            "version": "3.0.0",
            "licenses": [{"license": {"name": "BSD-3-Clause"}}],
        },
    ],
}

SPDX_MINIMAL = {
    "spdxVersion": "SPDX-2.3",
    "SPDXID": "SPDXRef-DOCUMENT",
    "packages": [
        {
            "name": "numpy",
            "versionInfo": "1.26.0",
            "licenseConcluded": "BSD-3-Clause",
            "externalRefs": [
                {"referenceType": "purl", "referenceLocator": "pkg:pypi/numpy@1.26.0"}
            ],
        },
    ],
}

CYCLONEDX_WITH_GPL = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [
        {
            "name": "gpl-pkg",
            "version": "1.0.0",
            "licenses": [{"license": {"id": "GPL-3.0"}}],
        },
        {
            "name": "mit-pkg",
            "version": "2.0.0",
            "licenses": [{"license": {"id": "MIT"}}],
        },
    ],
}


class TestSBOMParserDetectFormat:
    def test_detects_cyclonedx(self):
        parser = SBOMParser()
        assert parser._detect_format(CYCLONEDX_MINIMAL) == "CycloneDX"

    def test_detects_spdx(self):
        parser = SBOMParser()
        assert parser._detect_format(SPDX_MINIMAL) == "SPDX"

    def test_unknown_format(self):
        parser = SBOMParser()
        assert parser._detect_format({"foo": "bar"}) is None


class TestParseSBOM:
    def test_cyclonedx_success(self):
        result = parse_sbom(json.dumps(CYCLONEDX_MINIMAL))
        assert result["status"] == "success"
        assert result["format"] == "CycloneDX"
        assert len(result["packages"]) == 2
        assert result["packages"][0]["name"] == "requests"
        assert result["packages"][0]["license"] == "Apache-2.0"

    def test_spdx_success(self):
        result = parse_sbom(json.dumps(SPDX_MINIMAL))
        assert result["status"] == "success"
        assert result["format"] == "SPDX"
        assert len(result["packages"]) == 1
        assert result["packages"][0]["name"] == "numpy"
        assert result["packages"][0]["purl"] == "pkg:pypi/numpy@1.26.0"

    def test_invalid_json(self):
        result = parse_sbom("not valid json {{{")
        assert result["status"] == "error"
        assert "JSON" in result["message"]

    def test_unsupported_format(self):
        result = parse_sbom(json.dumps({"something": "else"}))
        assert result["status"] == "error"
        assert "Unsupported" in result["message"]

    def test_copyleft_detection(self):
        result = parse_sbom(json.dumps(CYCLONEDX_WITH_GPL))
        assert result["status"] == "success"
        gpl_pkg = next(p for p in result["packages"] if p["name"] == "gpl-pkg")
        mit_pkg = next(p for p in result["packages"] if p["name"] == "mit-pkg")
        assert gpl_pkg["is_copyleft"] is True
        assert mit_pkg["is_copyleft"] is False

    def test_summary_statistics(self):
        result = parse_sbom(json.dumps(CYCLONEDX_WITH_GPL))
        summary = result["summary"]
        assert summary["total_packages"] == 2
        assert summary["copyleft_packages"] == 1
        assert summary["unique_licenses"] == 2

    def test_license_expression_fallback(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "name": "dual-pkg",
                    "version": "1.0",
                    "licenses": [{"expression": "MIT OR Apache-2.0"}],
                }
            ],
        }
        result = parse_sbom(json.dumps(sbom))
        assert result["packages"][0]["license"] == "MIT OR Apache-2.0"

    def test_spdx_noassertion_fallback(self):
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "unknown-lic",
                    "versionInfo": "1.0",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                }
            ],
        }
        result = parse_sbom(json.dumps(sbom))
        assert result["packages"][0]["license"] == "Unknown"
