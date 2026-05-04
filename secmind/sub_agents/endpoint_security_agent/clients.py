"""HTTP clients for CrowdStrike Falcon and Qualys VM.

Both are read-only here — listing hosts, detections, incidents, and vulnerability
data. Auth shapes:

- CrowdStrike: OAuth2 client_credentials → bearer token (cached per client instance)
- Qualys: HTTP basic auth on every call

Each client raises ``RuntimeError`` on auth failure or non-2xx responses with the
upstream message preserved so tool functions can surface a clean error.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)

_TIMEOUT = 30


# ---------------------------------------------------------------------------
# CrowdStrike Falcon
# ---------------------------------------------------------------------------


class FalconClient:
    """Minimal CrowdStrike Falcon REST client.

    Config keys consumed:
        FALCON_CLIENT_ID, FALCON_CLIENT_SECRET — required.
        FALCON_BASE_URL                        — optional; defaults to api.crowdstrike.com
                                                 (US-1). Other regions: api.us-2.crowdstrike.com,
                                                 api.eu-1.crowdstrike.com, api.us-gov-1.crowdstrike.com.
    """

    def __init__(self, config: dict):
        self.client_id = config.get("FALCON_CLIENT_ID")
        self.client_secret = config.get("FALCON_CLIENT_SECRET")
        self.base = (config.get("FALCON_BASE_URL") or "https://api.crowdstrike.com").rstrip("/")
        if not self.client_id or not self.client_secret:
            raise ValueError("FALCON_CLIENT_ID and FALCON_CLIENT_SECRET are required")
        self._token: Optional[str] = None
        self._token_expires_at: float = 0.0

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expires_at - 30:
            return self._token
        resp = requests.post(
            f"{self.base}/oauth2/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=_TIMEOUT,
        )
        if resp.status_code != 201 and resp.status_code != 200:
            raise RuntimeError(f"Falcon auth failed (HTTP {resp.status_code}): {resp.text[:200]}")
        body = resp.json() or {}
        self._token = body.get("access_token")
        self._token_expires_at = time.time() + int(body.get("expires_in", 1800))
        if not self._token:
            raise RuntimeError("Falcon auth response did not include access_token")
        return self._token

    def _get(self, path: str, params: Optional[dict] = None) -> dict:
        resp = requests.get(
            f"{self.base}{path}",
            headers={"Authorization": f"Bearer {self._get_token()}"},
            params=params,
            timeout=_TIMEOUT,
        )
        if not resp.ok:
            raise RuntimeError(f"Falcon GET {path} failed (HTTP {resp.status_code}): {resp.text[:200]}")
        return resp.json() or {}

    def _post(self, path: str, json_body: dict) -> dict:
        resp = requests.post(
            f"{self.base}{path}",
            headers={
                "Authorization": f"Bearer {self._get_token()}",
                "Content-Type": "application/json",
            },
            json=json_body,
            timeout=_TIMEOUT,
        )
        if not resp.ok:
            raise RuntimeError(f"Falcon POST {path} failed (HTTP {resp.status_code}): {resp.text[:200]}")
        return resp.json() or {}

    # -- Hosts -----------------------------------------------------------

    def list_host_ids(self, filter_str: str = "", limit: int = 100) -> list[str]:
        params: dict[str, Any] = {"limit": min(limit, 5000)}
        if filter_str:
            params["filter"] = filter_str
        body = self._get("/devices/queries/devices/v1", params=params)
        return list(body.get("resources", []) or [])

    def get_hosts(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        # The "v2" entities endpoint accepts up to 500 ids per call.
        out: list[dict] = []
        for chunk in (ids[i : i + 500] for i in range(0, len(ids), 500)):
            body = self._get("/devices/entities/devices/v2", params=[("ids", i) for i in chunk])
            out.extend(body.get("resources", []) or [])
        return out

    def list_hosts(self, filter_str: str = "", limit: int = 100) -> list[dict]:
        ids = self.list_host_ids(filter_str=filter_str, limit=limit)
        return self.get_hosts(ids)

    # -- Detections ------------------------------------------------------

    def list_detection_ids(self, filter_str: str = "", limit: int = 100) -> list[str]:
        params: dict[str, Any] = {"limit": min(limit, 9999), "sort": "created_timestamp.desc"}
        if filter_str:
            params["filter"] = filter_str
        body = self._get("/detects/queries/detects/v1", params=params)
        return list(body.get("resources", []) or [])

    def get_detections(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        body = self._post("/detects/entities/summaries/GET/v1", {"ids": ids})
        return list(body.get("resources", []) or [])

    def list_detections(self, filter_str: str = "", limit: int = 100) -> list[dict]:
        ids = self.list_detection_ids(filter_str=filter_str, limit=limit)
        return self.get_detections(ids)

    # -- Incidents -------------------------------------------------------

    def list_incident_ids(self, filter_str: str = "", limit: int = 50) -> list[str]:
        params: dict[str, Any] = {"limit": min(limit, 500), "sort": "modified_timestamp.desc"}
        if filter_str:
            params["filter"] = filter_str
        body = self._get("/incidents/queries/incidents/v1", params=params)
        return list(body.get("resources", []) or [])

    def get_incidents(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        body = self._post("/incidents/entities/incidents/GET/v1", {"ids": ids})
        return list(body.get("resources", []) or [])

    def list_incidents(self, filter_str: str = "", limit: int = 50) -> list[dict]:
        ids = self.list_incident_ids(filter_str=filter_str, limit=limit)
        return self.get_incidents(ids)

    # -- Spotlight Vulnerabilities --------------------------------------

    def list_spotlight_vuln_ids(self, filter_str: str = "", limit: int = 100) -> list[str]:
        params: dict[str, Any] = {
            "limit": min(limit, 5000),
            "sort": "updated_timestamp.desc",
        }
        if filter_str:
            params["filter"] = filter_str
        body = self._get("/spotlight/queries/vulnerabilities/v1", params=params)
        return list(body.get("resources", []) or [])

    def get_spotlight_vulnerabilities(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        out: list[dict] = []
        for chunk in (ids[i : i + 400] for i in range(0, len(ids), 400)):
            body = self._get(
                "/spotlight/entities/vulnerabilities/v2",
                params=[("ids", i) for i in chunk],
            )
            out.extend(body.get("resources", []) or [])
        return out

    def list_spotlight_vulns(self, filter_str: str = "", limit: int = 100) -> list[dict]:
        ids = self.list_spotlight_vuln_ids(filter_str=filter_str, limit=limit)
        return self.get_spotlight_vulnerabilities(ids)

    # -- Custom IOCs ----------------------------------------------------

    def list_ioc_ids(self, filter_str: str = "", limit: int = 100) -> list[str]:
        params: dict[str, Any] = {"limit": min(limit, 2000)}
        if filter_str:
            params["filter"] = filter_str
        body = self._get("/iocs/queries/indicators/v1", params=params)
        return list(body.get("resources", []) or [])

    def get_iocs(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        body = self._post("/iocs/entities/indicators/GET/v1", {"ids": ids})
        return list(body.get("resources", []) or [])

    def list_iocs(self, filter_str: str = "", limit: int = 100) -> list[dict]:
        ids = self.list_ioc_ids(filter_str=filter_str, limit=limit)
        return self.get_iocs(ids)

    # -- Audit events ---------------------------------------------------

    def list_audit_event_ids(self, filter_str: str = "", limit: int = 100) -> list[str]:
        params: dict[str, Any] = {
            "limit": min(limit, 500),
            "sort": "time.desc",
        }
        if filter_str:
            params["filter"] = filter_str
        body = self._get("/audit-events/queries/audit-events/v1", params=params)
        return list(body.get("resources", []) or [])

    def get_audit_events(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        body = self._get(
            "/audit-events/entities/audit-events/v1",
            params=[("ids", i) for i in ids],
        )
        return list(body.get("resources", []) or [])

    def list_audit_events(self, filter_str: str = "", limit: int = 100) -> list[dict]:
        ids = self.list_audit_event_ids(filter_str=filter_str, limit=limit)
        return self.get_audit_events(ids)

    # -- Host groups ----------------------------------------------------

    def list_host_groups(self, filter_str: str = "", limit: int = 100) -> list[dict]:
        params: dict[str, Any] = {"limit": min(limit, 5000)}
        if filter_str:
            params["filter"] = filter_str
        body = self._get("/devices/combined/host-groups/v1", params=params)
        return list(body.get("resources", []) or [])

    # -- IOMs (Falcon Cloud Security — Indicators of Misconfiguration) --

    def list_iom_ids(self, filter_str: str = "", limit: int = 100) -> list[str]:
        params: dict[str, Any] = {
            "limit": min(limit, 500),
            "sort": "scan_time|desc",
        }
        if filter_str:
            params["filter"] = filter_str
        # ``/detects/queries/iom/v2`` is the current path in CrowdStrike's Cloud
        # Security IOM API. If your tenant exposes the older v1 path, adjust
        # this string and the entities endpoint below.
        body = self._get("/detects/queries/iom/v2", params=params)
        return list(body.get("resources", []) or [])

    def get_ioms(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        out: list[dict] = []
        for chunk in (ids[i : i + 100] for i in range(0, len(ids), 100)):
            body = self._get(
                "/detects/entities/iom/v2",
                params=[("ids", i) for i in chunk],
            )
            out.extend(body.get("resources", []) or [])
        return out

    def list_ioms(self, filter_str: str = "", limit: int = 100) -> list[dict]:
        ids = self.list_iom_ids(filter_str=filter_str, limit=limit)
        return self.get_ioms(ids)


# ---------------------------------------------------------------------------
# Qualys VM
# ---------------------------------------------------------------------------


class QualysClient:
    """Minimal Qualys VM REST client (XML-over-HTTPS).

    Config keys consumed:
        QUALYS_USERNAME, QUALYS_PASSWORD — required.
        QUALYS_BASE_URL                  — required; e.g. https://qualysapi.qualys.com
                                           (US1) or https://qualysapi.qg2.apps.qualys.com (US2),
                                           https://qualysapi.qualys.eu (EU), etc.

    Most Qualys endpoints return XML by default; we ask for JSON via the
    ``output_format=json`` parameter where supported (newer endpoints) and parse
    XML via stdlib for older ones.
    """

    def __init__(self, config: dict):
        self.user = config.get("QUALYS_USERNAME")
        self.password = config.get("QUALYS_PASSWORD")
        self.base = (config.get("QUALYS_BASE_URL") or "").rstrip("/")
        if not self.user or not self.password:
            raise ValueError("QUALYS_USERNAME and QUALYS_PASSWORD are required")
        if not self.base:
            raise ValueError("QUALYS_BASE_URL is required (e.g. https://qualysapi.qualys.com)")

    def _get_xml(self, path: str, params: Optional[dict] = None) -> str:
        resp = requests.get(
            f"{self.base}{path}",
            params=params,
            auth=(self.user, self.password),
            headers={"X-Requested-With": "Security Mind"},
            timeout=_TIMEOUT,
        )
        if not resp.ok:
            raise RuntimeError(f"Qualys GET {path} failed (HTTP {resp.status_code}): {resp.text[:200]}")
        return resp.text

    def _list_via_xml(self, path: str, params: dict, root_tag: str) -> list[dict]:
        from xml.etree import ElementTree as ET

        text = self._get_xml(path, params=params)
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            raise RuntimeError(f"Qualys returned invalid XML for {path}: {e}")
        out: list[dict] = []
        for item in root.iter(root_tag):
            row: dict[str, Any] = {}
            for child in item:
                row[child.tag] = (child.text or "").strip()
            out.append(row)
        return out

    # -- Assets ----------------------------------------------------------

    def list_assets(self, ips: str = "", limit: int = 100) -> list[dict]:
        params: dict[str, Any] = {"action": "list", "truncation_limit": limit}
        if ips:
            params["ips"] = ips
        return self._list_via_xml("/api/2.0/fo/asset/host/", params, root_tag="HOST")

    # -- Detections ------------------------------------------------------

    def list_host_detections(self, ips: str = "", severities: str = "", limit: int = 100) -> list[dict]:
        params: dict[str, Any] = {
            "action": "list",
            "truncation_limit": limit,
            "show_results": 0,  # keep payload small; surface QID + severity, not full vuln text
        }
        if ips:
            params["ips"] = ips
        if severities:
            params["severities"] = severities
        return self._list_via_xml(
            "/api/2.0/fo/asset/host/vm/detection/",
            params,
            root_tag="HOST",
        )

    # -- Scans -----------------------------------------------------------

    def list_scans(self, state: str = "", limit: int = 50) -> list[dict]:
        params: dict[str, Any] = {"action": "list"}
        if state:
            params["state"] = state
        scans = self._list_via_xml("/api/2.0/fo/scan/", params, root_tag="SCAN")
        return scans[:limit]

    # -- Knowledge Base --------------------------------------------------

    def get_kb_vuln(self, qid: str) -> Optional[dict]:
        """Fetch a single Knowledge Base entry by QID.

        Returns a flat-ish dict where leaf XML elements become string values
        and nested lists (CVE_LIST, VENDOR_REFERENCE_LIST, etc.) become lists
        of strings or dicts. ``None`` if the QID is unknown.
        """
        from xml.etree import ElementTree as ET

        text = self._get_xml(
            "/api/2.0/fo/knowledge_base/vuln/",
            params={"action": "list", "ids": qid},
        )
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            raise RuntimeError(f"Qualys KB returned invalid XML: {e}")

        vuln = next(iter(root.iter("VULN")), None)
        if vuln is None:
            return None

        out: dict[str, Any] = {}
        for child in vuln:
            if len(child) == 0:
                out[child.tag] = (child.text or "").strip()
                continue
            items: list[Any] = []
            for sub in child:
                if len(sub) == 0:
                    val = (sub.text or "").strip()
                    if val:
                        items.append(val)
                else:
                    items.append({c.tag: (c.text or "").strip() for c in sub})
            out[child.tag] = items
        return out
