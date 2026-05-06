from unittest.mock import patch, MagicMock

import pytest

from secmind.sub_agents.threat_modeling_agent.threat_modeler import (
    _build_report_filename,
    _merge_recommendations,
    _dedupe_vulns,
    _populate_cross_references,
    _aggregate_risk,
)


class TestBuildReportFilename:
    def test_basic_name(self):
        name = _build_report_filename({"name": "MyApp"})
        assert "MyApp" in name
        assert name.startswith("Threat Model-")
        assert name.endswith(".html")

    def test_missing_name(self):
        name = _build_report_filename({})
        assert "Unknown App" in name

    def test_none_input(self):
        name = _build_report_filename(None)
        assert "Unknown App" in name

    def test_sanitizes_slashes(self):
        name = _build_report_filename({"name": "path/to\\app"})
        assert "/" not in name.split("-", 2)[1]
        assert "\\" not in name


class TestMergeRecommendations:
    def test_merge_new_category(self):
        target = {}
        _merge_recommendations(target, {"auth": ["Use MFA"]})
        assert target == {"auth": ["Use MFA"]}

    def test_merge_existing_category(self):
        target = {"auth": ["Use MFA"]}
        _merge_recommendations(target, {"auth": ["Rotate keys", "Use MFA"]})
        assert target["auth"] == ["Use MFA", "Rotate keys"]

    def test_empty_addition(self):
        target = {"a": ["x"]}
        _merge_recommendations(target, {})
        assert target == {"a": ["x"]}

    def test_none_addition(self):
        target = {"a": ["x"]}
        _merge_recommendations(target, None)
        assert target == {"a": ["x"]}


class TestDedupeVulns:
    def test_removes_duplicates(self):
        vulns = [
            {"vulnerability": "SQL Injection", "component": "api"},
            {"vulnerability": "sql injection", "component": "API"},
            {"vulnerability": "XSS", "component": "web"},
        ]
        result = _dedupe_vulns(vulns)
        assert len(result) == 2

    def test_adds_cwe_id_default(self):
        vulns = [{"vulnerability": "test", "component": "x"}]
        result = _dedupe_vulns(vulns)
        assert result[0]["cwe_id"] is None

    def test_empty_list(self):
        assert _dedupe_vulns([]) == []


class TestPopulateCrossReferences:
    def test_bidirectional_linking(self):
        threats = [
            {"technique_id": "T1", "cross_references": ["T2"]},
            {"technique_id": "T2", "cross_references": []},
        ]
        _populate_cross_references(threats)
        assert "T1" in threats[1]["cross_references"]

    def test_no_cross_references(self):
        threats = [
            {"technique_id": "T1"},
            {"technique_id": "T2"},
        ]
        _populate_cross_references(threats)
        assert threats[0].get("cross_references") is None


class TestAggregateRisk:
    def test_single_framework(self):
        scores = {"stride": 75}
        threats = [{"framework": "stride"}, {"framework": "stride"}]
        risk = _aggregate_risk(scores, threats)
        assert 0 <= risk <= 100
        assert risk == 75

    def test_multiple_frameworks(self):
        scores = {"stride": 80, "dread": 60}
        threats = [{"framework": "stride"}, {"framework": "dread"}]
        risk = _aggregate_risk(scores, threats)
        assert 0 <= risk <= 100

    def test_empty_scores(self):
        assert _aggregate_risk({}, []) == 0

    def test_clamped_to_100(self):
        scores = {"stride": 200}
        risk = _aggregate_risk(scores, [])
        assert risk == 100
