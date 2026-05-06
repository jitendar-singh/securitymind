from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from secmind.sub_agents.vuln_triage_agent.vulnerability_triage import (
    CVSSExtractor,
    VulnerabilityTriager,
)


class TestCVSSExtractor:
    def test_extract_from_nvd_v31(self):
        cve = SimpleNamespace(v31severity="HIGH", v31score=8.1, v31vector="AV:N/AC:H")
        sev, score, vec = CVSSExtractor.extract_from_nvd(cve)
        assert sev == "HIGH"
        assert score == 8.1

    def test_extract_from_nvd_v40(self):
        cve = SimpleNamespace(v40severity="CRITICAL", v40score=9.8, v40vector="AV:N")
        sev, score, vec = CVSSExtractor.extract_from_nvd(cve)
        assert sev == "CRITICAL"

    def test_extract_from_nvd_no_cvss(self):
        cve = SimpleNamespace()
        sev, score, vec = CVSSExtractor.extract_from_nvd(cve)
        assert sev is None
        assert score is None

    def test_extract_from_cveorg_v31(self):
        metric = {"cvssV3_1": {"baseSeverity": "MEDIUM", "baseScore": 5.5, "vectorString": "AV:L"}}
        sev, score, vec = CVSSExtractor.extract_from_cveorg(metric)
        assert sev == "MEDIUM"
        assert score == 5.5

    def test_extract_from_cveorg_empty(self):
        sev, score, vec = CVSSExtractor.extract_from_cveorg({})
        assert sev is None


class TestVulnerabilityTriager:
    @patch("secmind.sub_agents.vuln_triage_agent.vulnerability_triage.get_http_client")
    @patch("secmind.sub_agents.vuln_triage_agent.vulnerability_triage.nvdlib")
    def test_nvd_hit(self, mock_nvdlib, mock_get_http):
        mock_cve = SimpleNamespace(
            id="CVE-2024-1234",
            v31severity="HIGH",
            v31score=8.5,
            v31vector="AV:N",
            descriptions=[SimpleNamespace(value="Buffer overflow")],
            published="2024-01-01",
            lastModified="2024-01-02",
        )
        mock_nvdlib.searchCVE.return_value = [mock_cve]

        mock_memory = MagicMock()
        mock_memory.get_triage_result.return_value = None

        triager = VulnerabilityTriager(memory_manager=mock_memory)
        result = triager.triage("Check CVE-2024-1234 please")

        assert result["severity"] == "HIGH"
        assert result["details"]["cve_id"] == "CVE-2024-1234"
        assert result["details"]["source"] == "NVD"
        mock_memory.add_triage_result.assert_called_once()

    @patch("secmind.sub_agents.vuln_triage_agent.vulnerability_triage.get_http_client")
    @patch("secmind.sub_agents.vuln_triage_agent.vulnerability_triage.nvdlib")
    def test_nvd_miss_cveorg_hit(self, mock_nvdlib, mock_get_http):
        mock_nvdlib.searchCVE.return_value = []

        mock_http = MagicMock()
        mock_http.get_json.return_value = {
            "containers": {
                "cna": {
                    "descriptions": [{"value": "Use after free"}],
                    "metrics": [{"cvssV3_1": {"baseSeverity": "CRITICAL", "baseScore": 9.8, "vectorString": "AV:N"}}],
                }
            }
        }
        mock_get_http.return_value = mock_http

        mock_memory = MagicMock()
        mock_memory.get_triage_result.return_value = None

        triager = VulnerabilityTriager(memory_manager=mock_memory)
        triager.http_client = mock_http
        result = triager.triage("CVE-2024-5678")

        assert result["severity"] == "CRITICAL"
        assert result["details"]["source"] == "cve.org"

    @patch("secmind.sub_agents.vuln_triage_agent.vulnerability_triage.get_http_client")
    @patch("secmind.sub_agents.vuln_triage_agent.vulnerability_triage.nvdlib")
    def test_both_fail(self, mock_nvdlib, mock_get_http):
        mock_nvdlib.searchCVE.side_effect = Exception("NVD down")
        mock_http = MagicMock()
        mock_http.get_json.return_value = None
        mock_get_http.return_value = mock_http

        mock_memory = MagicMock()
        mock_memory.get_triage_result.return_value = None

        triager = VulnerabilityTriager(memory_manager=mock_memory)
        triager.http_client = mock_http
        result = triager.triage("CVE-2024-9999")

        assert result["severity"] == "ERROR"

    def test_no_cve_id(self):
        mock_memory = MagicMock()
        triager = VulnerabilityTriager(memory_manager=mock_memory)
        result = triager.triage("no vulnerability identifier here")
        assert result["severity"] == "UNKNOWN"

    @patch("secmind.sub_agents.vuln_triage_agent.vulnerability_triage.get_http_client")
    def test_cache_hit(self, mock_get_http):
        mock_memory = MagicMock()
        mock_memory.get_triage_result.return_value = {
            "severity": "HIGH",
            "recommendation": "Patch",
            "details": {"cve_id": "CVE-2024-1234", "source": "NVD"},
        }
        triager = VulnerabilityTriager(memory_manager=mock_memory)
        result = triager.triage("CVE-2024-1234")
        assert result["severity"] == "HIGH"
        assert "(cached)" in result["details"]["source"]
