from unittest.mock import patch, MagicMock

import pytest


class TestFirstActive:
    @patch("secmind.sub_agents.endpoint_security_agent.agent.get_store")
    @patch("secmind.sub_agents.endpoint_security_agent.agent.current_user_id")
    def test_returns_matching_integration(self, mock_uid, mock_store):
        mock_uid.return_value = 1
        mock_store.return_value.iter_active.return_value = [
            {"provider": "crowdstrike", "name": "cs-main", "config": {"key": "k"}},
        ]
        from secmind.sub_agents.endpoint_security_agent.agent import _first_active
        rec = _first_active("crowdstrike")
        assert rec is not None
        assert rec["provider"] == "crowdstrike"

    @patch("secmind.sub_agents.endpoint_security_agent.agent.get_store")
    @patch("secmind.sub_agents.endpoint_security_agent.agent.current_user_id")
    def test_returns_none_no_match(self, mock_uid, mock_store):
        mock_uid.return_value = 1
        mock_store.return_value.iter_active.return_value = []
        from secmind.sub_agents.endpoint_security_agent.agent import _first_active
        assert _first_active("crowdstrike") is None

    @patch("secmind.sub_agents.endpoint_security_agent.agent.current_user_id")
    def test_returns_none_no_user(self, mock_uid):
        mock_uid.return_value = None
        from secmind.sub_agents.endpoint_security_agent.agent import _first_active
        assert _first_active("crowdstrike") is None


class TestCrowdstrikeListHosts:
    @patch("secmind.sub_agents.endpoint_security_agent.agent._cache")
    @patch("secmind.sub_agents.endpoint_security_agent.agent._first_active")
    def test_no_integration(self, mock_fa, mock_cache):
        mock_fa.return_value = None
        from secmind.sub_agents.endpoint_security_agent.agent import crowdstrike_list_hosts
        result = crowdstrike_list_hosts()
        assert result["status"] == "error"
        assert "CrowdStrike" in result["message"]

    @patch("secmind.sub_agents.endpoint_security_agent.agent._cache")
    @patch("secmind.sub_agents.endpoint_security_agent.agent._first_active")
    def test_with_integration(self, mock_fa, mock_cache):
        mock_fa.return_value = {"provider": "crowdstrike", "name": "main", "config": {"key": "x"}}
        mock_cache.cached.return_value = {
            "status": "success",
            "message": "Returned 2 host(s)",
            "data": {"hosts": [{"id": "h1"}, {"id": "h2"}]},
        }
        from secmind.sub_agents.endpoint_security_agent.agent import crowdstrike_list_hosts
        result = crowdstrike_list_hosts()
        assert result["status"] == "success"
        assert len(result["data"]["hosts"]) == 2


class TestCrowdstrikeGetHost:
    @patch("secmind.sub_agents.endpoint_security_agent.agent._first_active")
    def test_empty_device_id(self, mock_fa):
        from secmind.sub_agents.endpoint_security_agent.agent import crowdstrike_get_host
        result = crowdstrike_get_host("")
        assert result["status"] == "error"
        assert "required" in result["message"]


class TestQualysListAssets:
    @patch("secmind.sub_agents.endpoint_security_agent.agent._cache")
    @patch("secmind.sub_agents.endpoint_security_agent.agent._first_active")
    def test_no_integration(self, mock_fa, mock_cache):
        mock_fa.return_value = None
        from secmind.sub_agents.endpoint_security_agent.agent import qualys_list_assets
        result = qualys_list_assets()
        assert result["status"] == "error"
        assert "Qualys" in result["message"]


class TestClearEndpointCache:
    @patch("secmind.sub_agents.endpoint_security_agent.agent._cache")
    def test_clear(self, mock_cache_module):
        mock_cache_module.clear_all.return_value = 5
        from secmind.sub_agents.endpoint_security_agent.agent import clear_endpoint_cache
        result = clear_endpoint_cache()
        assert result["status"] == "success"


class TestHelpers:
    def test_ok(self):
        from secmind.sub_agents.endpoint_security_agent.agent import _ok
        result = _ok("msg", {"x": 1})
        assert result == {"status": "success", "message": "msg", "data": {"x": 1}}

    def test_err(self):
        from secmind.sub_agents.endpoint_security_agent.agent import _err
        result = _err("fail")
        assert result == {"status": "error", "message": "fail"}
