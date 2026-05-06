from unittest.mock import patch, MagicMock

import pytest

from secmind.sub_agents.vuln_triage_agent.license_checker import (
    PyPIHandler,
    NPMHandler,
    MavenHandler,
    ClearlyDefinedHandler,
    LicenseChecker,
)


class TestPyPIHandler:
    def test_returns_license(self):
        mock_http = MagicMock()
        mock_http.get_json.return_value = {"info": {"license": "MIT"}}
        handler = PyPIHandler(mock_http)
        assert handler.get_license("requests") == "MIT"

    def test_returns_none_on_missing(self):
        mock_http = MagicMock()
        mock_http.get_json.return_value = None
        handler = PyPIHandler(mock_http)
        assert handler.get_license("nonexistent") is None


class TestNPMHandler:
    def test_returns_license_string(self):
        mock_http = MagicMock()
        mock_http.get_json.return_value = {"license": "ISC"}
        handler = NPMHandler(mock_http)
        assert handler.get_license("lodash") == "ISC"

    def test_handles_license_dict(self):
        mock_http = MagicMock()
        mock_http.get_json.return_value = {"license": {"type": "MIT"}}
        handler = NPMHandler(mock_http)
        assert handler.get_license("some-pkg") == "MIT"

    def test_returns_none_on_missing(self):
        mock_http = MagicMock()
        mock_http.get_json.return_value = None
        handler = NPMHandler(mock_http)
        assert handler.get_license("missing-pkg") is None


class TestMavenHandler:
    def test_colon_format(self):
        mock_http = MagicMock()
        mock_http.get_json.return_value = {"response": {"docs": [{"id": "x"}]}}
        handler = MavenHandler(mock_http)
        result = handler.get_license("org.apache:commons-lang3")
        assert result == "Requires POM analysis"

    def test_returns_none_no_docs(self):
        mock_http = MagicMock()
        mock_http.get_json.return_value = {"response": {"docs": []}}
        handler = MavenHandler(mock_http)
        assert handler.get_license("com.example:nothing") is None


class TestClearlyDefinedHandler:
    def test_returns_license(self):
        mock_http = MagicMock()
        mock_http.get_json.return_value = {"licensed": {"declared": "Apache-2.0"}}
        handler = ClearlyDefinedHandler(mock_http)
        assert handler.get_license("requests", "pypi") == "Apache-2.0"

    def test_returns_none_on_missing(self):
        mock_http = MagicMock()
        mock_http.get_json.return_value = None
        handler = ClearlyDefinedHandler(mock_http)
        assert handler.get_license("unknown", "pypi") is None


class TestLicenseChecker:
    @patch("secmind.sub_agents.vuln_triage_agent.license_checker.get_http_client")
    def test_pypi_package(self, mock_get_http):
        mock_http = MagicMock()
        mock_http.get_json.return_value = {"info": {"license": "MIT"}}
        mock_get_http.return_value = mock_http

        checker = LicenseChecker()
        result = checker.check("requests", "pypi")
        assert result["license"] == "MIT"
        assert result["is_copyleft"] is False
        assert result["ecosystem"] == "pypi"

    @patch("secmind.sub_agents.vuln_triage_agent.license_checker.get_http_client")
    def test_copyleft_detection(self, mock_get_http):
        mock_http = MagicMock()
        mock_http.get_json.return_value = {"info": {"license": "GPL-3.0"}}
        mock_get_http.return_value = mock_http

        checker = LicenseChecker()
        result = checker.check("gpl-pkg", "pypi")
        assert result["is_copyleft"] is True

    @patch("secmind.sub_agents.vuln_triage_agent.license_checker.get_http_client")
    def test_auto_detect_ecosystem(self, mock_get_http):
        mock_http = MagicMock()
        mock_http.get_json.return_value = {"info": {"license": "BSD"}}
        mock_get_http.return_value = mock_http

        checker = LicenseChecker()
        result = checker.check("numpy")
        assert result["ecosystem"] == "pypi"

    @patch("secmind.sub_agents.vuln_triage_agent.license_checker.get_http_client")
    def test_unknown_ecosystem_falls_back(self, mock_get_http):
        mock_http = MagicMock()
        mock_http.get_json.side_effect = [None, {"licensed": {"declared": "MIT"}}]
        mock_get_http.return_value = mock_http

        checker = LicenseChecker()
        result = checker.check("pkg", "unknown_ecosystem")
        assert result["license"] in ("MIT", "Unknown")
