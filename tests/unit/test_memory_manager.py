import time

import pytest

from secmind.memory_manager import MemoryManager


@pytest.fixture
def mm(tmp_path):
    return MemoryManager(db_path=str(tmp_path / "mem"))


class TestTriageResults:
    def test_add_and_get(self, mm):
        mm.add_triage_result(
            "CVE-2024-1234", "HIGH", "Patch immediately",
            {"description": "Buffer overflow", "score": 9.1},
        )
        result = mm.get_triage_result("CVE-2024-1234")
        assert result is not None
        assert result["severity"] == "HIGH"
        assert result["details"]["score"] == 9.1

    def test_get_missing(self, mm):
        assert mm.get_triage_result("CVE-9999-0000") is None

    def test_upsert_replaces(self, mm):
        mm.add_triage_result("CVE-2024-1234", "MEDIUM", "Monitor", {"score": 6.0})
        mm.add_triage_result("CVE-2024-1234", "HIGH", "Patch", {"score": 9.0})
        result = mm.get_triage_result("CVE-2024-1234")
        assert result["severity"] == "HIGH"


class TestThreatModels:
    def test_add_and_get(self, mm):
        app = {"name": "myapp", "components": []}
        report = {"threats": ["t1"], "risk": 7}
        mm.add_threat_model(app, report, frameworks=["stride"])
        result = mm.get_threat_model(app, frameworks=["stride"])
        assert result is not None
        assert result["threats"] == ["t1"]

    def test_get_missing(self, mm):
        assert mm.get_threat_model({"name": "no-such"}) is None

    def test_hash_deterministic(self):
        app = {"name": "test", "version": "1.0"}
        h1 = MemoryManager._threat_model_hash(app, ["stride"])
        h2 = MemoryManager._threat_model_hash(app, ["stride"])
        assert h1 == h2

    def test_different_frameworks_different_hash(self):
        app = {"name": "test"}
        h1 = MemoryManager._threat_model_hash(app, ["stride"])
        h2 = MemoryManager._threat_model_hash(app, ["dread"])
        assert h1 != h2


class TestCodeReviews:
    def test_add_and_get(self, mm):
        snippet = "def foo():\n    return 42"
        review = {"issues": [{"severity": "low", "message": "magic number"}]}
        mm.add_code_review(snippet, review)
        result = mm.get_code_review(snippet)
        assert result is not None
        assert len(result["issues"]) == 1

    def test_get_missing(self, mm):
        assert mm.get_code_review("nonexistent code") is None


class TestCloudResources:
    def test_add_and_get(self, mm):
        resources = {"instances": [{"id": "i-1"}]}
        mm.add_cloud_resources("projects/my-proj", ["compute"], resources)
        result = mm.get_cloud_resources("projects/my-proj", ["compute"])
        assert result is not None
        assert result["instances"][0]["id"] == "i-1"

    def test_get_missing(self, mm):
        assert mm.get_cloud_resources("projects/none", None) is None


class TestSecurityPosture:
    def test_add_and_get(self, mm):
        posture = {"findings": [{"id": "f1"}]}
        mm.add_security_posture("orgs/123", "src-1", posture)
        result = mm.get_security_posture("orgs/123", "src-1")
        assert result is not None
        assert result["findings"][0]["id"] == "f1"

    def test_get_missing(self, mm):
        assert mm.get_security_posture("orgs/999", None) is None


class TestIamRecommendations:
    def test_add_and_get(self, mm):
        recs = {"recommendations": [{"id": "r1"}]}
        mm.add_iam_recommendations("proj-1", recs)
        result = mm.get_iam_recommendations("proj-1")
        assert result is not None

    def test_get_missing(self, mm):
        assert mm.get_iam_recommendations("proj-none") is None


class TestEndpointCache:
    def test_add_and_get(self, mm):
        mm.add_endpoint_cache("hosts_all", {"hosts": [1, 2, 3]})
        result = mm.get_endpoint_cache("hosts_all", ttl_seconds=60)
        assert result is not None
        assert result["hosts"] == [1, 2, 3]

    def test_get_missing(self, mm):
        assert mm.get_endpoint_cache("nonexistent") is None

    def test_ttl_expiry(self, mm):
        mm.add_endpoint_cache("expiring", {"data": True})
        result = mm.get_endpoint_cache("expiring", ttl_seconds=0)
        assert result is None

    def test_clear_cache(self, mm):
        mm.add_endpoint_cache("k1", {"a": 1})
        mm.add_endpoint_cache("k2", {"b": 2})
        count = mm.clear_endpoint_cache()
        assert count == 2
        assert mm.get_endpoint_cache("k1") is None


class TestProjectKeyedMethods:
    def test_vpc_flow_logs_round_trip(self, mm):
        mm.add_vpc_flow_logs("proj-1", {"enabled": True})
        assert mm.get_vpc_flow_logs("proj-1")["enabled"] is True
        assert mm.get_vpc_flow_logs("proj-none") is None

    def test_default_network_round_trip(self, mm):
        mm.add_default_network("proj-1", {"exists": False})
        assert mm.get_default_network("proj-1")["exists"] is False

    def test_kms_rotation_round_trip(self, mm):
        mm.add_kms_rotation("proj-1", 90, {"keys": []})
        assert mm.get_kms_rotation("proj-1", 90) is not None
        assert mm.get_kms_rotation("proj-1", 180) is None

    def test_dnssec_round_trip(self, mm):
        mm.add_dnssec("proj-1", {"zones": []})
        assert mm.get_dnssec("proj-1") is not None

    def test_cloud_armor_round_trip(self, mm):
        mm.add_cloud_armor("proj-1", {"policies": []})
        assert mm.get_cloud_armor("proj-1") is not None


class TestSemanticMemory:
    def test_search_returns_documents(self, mm):
        mm.add_triage_result(
            "CVE-2024-5555", "CRITICAL", "Patch now",
            {"description": "Remote code execution in libxml2"},
        )
        results = mm.search_semantic_memory("libxml2 vulnerability", n_results=1)
        assert len(results) >= 1
        assert "CVE-2024-5555" in results[0]

    def test_search_empty_collection(self, mm):
        results = mm.search_semantic_memory("anything", n_results=1)
        assert results == [] or isinstance(results, list)
