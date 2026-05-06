import pytest

from secmind.sub_agents.vuln_triage_agent.utils import (
    extract_cve_id,
    is_copyleft_license,
    get_severity_from_score,
    get_recommendation,
    detect_ecosystem,
    sanitize_input,
)
from secmind.sub_agents.vuln_triage_agent.constants import COPYLEFT_LICENSES


class TestExtractCveId:
    def test_standard_cve(self):
        assert extract_cve_id("Found CVE-2023-1234 in package") == "CVE-2023-1234"

    def test_lowercase_cve(self):
        assert extract_cve_id("see cve-2024-56789") == "CVE-2024-56789"

    def test_no_cve(self):
        assert extract_cve_id("no vulnerability here") is None

    def test_empty_string(self):
        assert extract_cve_id("") is None

    def test_none_input(self):
        assert extract_cve_id(None) is None

    def test_long_cve_number(self):
        assert extract_cve_id("CVE-2024-1234567") == "CVE-2024-1234567"


class TestIsCopyleftLicense:
    def test_gpl3_is_copyleft(self):
        assert is_copyleft_license("GPL-3.0", COPYLEFT_LICENSES) is True

    def test_mit_is_not_copyleft(self):
        assert is_copyleft_license("MIT", COPYLEFT_LICENSES) is False

    def test_unknown_returns_false(self):
        assert is_copyleft_license("unknown", COPYLEFT_LICENSES) is False

    def test_empty_returns_false(self):
        assert is_copyleft_license("", COPYLEFT_LICENSES) is False

    def test_agpl_is_copyleft(self):
        assert is_copyleft_license("AGPL-3.0", COPYLEFT_LICENSES) is True


class TestGetSeverityFromScore:
    def test_critical(self):
        assert get_severity_from_score(9.8) == "CRITICAL"

    def test_high(self):
        assert get_severity_from_score(9.2) == "HIGH"

    def test_medium(self):
        assert get_severity_from_score(7.5) == "MEDIUM"

    def test_low(self):
        assert get_severity_from_score(3.0) == "LOW"

    def test_zero(self):
        assert get_severity_from_score(0.0) == "LOW"

    def test_boundary_critical(self):
        assert get_severity_from_score(9.5) == "CRITICAL"

    def test_boundary_high(self):
        assert get_severity_from_score(9.0) == "HIGH"

    def test_boundary_medium(self):
        assert get_severity_from_score(7.0) == "MEDIUM"


class TestGetRecommendation:
    def test_critical_recommendation(self):
        rec = get_recommendation("CRITICAL")
        assert "immediately" in rec.lower() or "critical" in rec.lower()

    def test_unknown_recommendation(self):
        rec = get_recommendation("UNKNOWN")
        assert rec  # non-empty

    def test_nonexistent_severity(self):
        rec = get_recommendation("NONEXISTENT")
        assert rec  # falls back to UNKNOWN


class TestDetectEcosystem:
    def test_npm_scoped(self):
        assert detect_ecosystem("@angular/core") == "npm"

    def test_maven_dot_notation(self):
        assert detect_ecosystem("com.google.guava") == "maven"

    def test_maven_colon_notation(self):
        assert detect_ecosystem("org.apache:commons-lang3") == "maven"

    def test_pypi_simple_name(self):
        assert detect_ecosystem("requests") == "pypi"

    def test_empty_string(self):
        assert detect_ecosystem("") == "unknown"


class TestSanitizeInput:
    def test_truncation(self):
        result = sanitize_input("a" * 2000, max_length=10)
        assert len(result) == 10

    def test_removes_angle_brackets(self):
        result = sanitize_input("<script>alert('xss')</script>")
        assert "<" not in result
        assert ">" not in result

    def test_empty_string(self):
        assert sanitize_input("") == ""

    def test_none_input(self):
        assert sanitize_input(None) == ""

    def test_strips_whitespace(self):
        result = sanitize_input("  hello  ")
        assert result == "hello"
