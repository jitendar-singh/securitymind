"""Hostname/IP normalization and pure cross-vendor join helpers.

Kept framework-free so it can be unit-tested without ADK or any cloud creds.
The agent.py tool layer wraps these with envelopes, caching, and integration
lookup.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Iterable, Optional

logger = logging.getLogger(__name__)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def normalize_hostname(value: str) -> tuple[str, str]:
    """Return ``(short, fqdn)``. Falcon stores FQDN, Qualys often stores short.

    >>> normalize_hostname("web-01.acme.local")
    ('web-01', 'web-01.acme.local')
    >>> normalize_hostname("web-01")
    ('web-01', '')
    """
    s = (value or "").strip().lower()
    short = s.split(".")[0]
    fqdn = s if "." in s else ""
    return short, fqdn


def falcon_filter_for(target: str) -> str:
    """Build a Falcon FQL filter clause that matches a host by IP or hostname.

    Comma in FQL means AND; the empty/short branch returns just one clause.
    """
    target = (target or "").strip()
    if not target:
        return ""
    if is_ip(target):
        # local_ip first; many fleets keep external_ip null.
        return f"host_info.local_ip:'{target}'"
    return f"host_info.hostname:'{target}'"


def cves_from_falcon_spotlight(vulns: Iterable[dict]) -> set[str]:
    """Best-effort extract CVEs from Spotlight vuln rows.

    Spotlight's v2 entity payload has ``cve.id`` (e.g. "CVE-2024-3094"). Older
    payloads expose ``cve_id``. Be forgiving.
    """
    out: set[str] = set()
    for v in vulns or []:
        cve_obj = v.get("cve") or {}
        cve_id = cve_obj.get("id") or v.get("cve_id")
        if cve_id:
            out.add(cve_id.upper())
    return out


def severity_counts_from_falcon_spotlight(vulns: Iterable[dict]) -> dict:
    crit = high = medium = low = 0
    for v in vulns or []:
        sev = ((v.get("cve") or {}).get("severity") or v.get("severity") or "").upper()
        if sev == "CRITICAL":
            crit += 1
        elif sev == "HIGH":
            high += 1
        elif sev == "MEDIUM":
            medium += 1
        elif sev == "LOW":
            low += 1
    return {"critical": crit, "high": high, "medium": medium, "low": low}


def first_match_by_hostname(rows: Iterable[dict], target: str, *fields: str) -> Optional[dict]:
    """Return the first row whose ``fields`` (any) match the target's short or FQDN form.

    Comparison is case-insensitive. Useful for picking a Falcon device or
    Qualys asset out of a list when matching by hostname.
    """
    short, fqdn = normalize_hostname(target)
    candidates = {short}
    if fqdn:
        candidates.add(fqdn)
    for row in rows or []:
        for field in fields:
            value = (row.get(field) or "").strip().lower()
            if not value:
                continue
            if value in candidates:
                return row
            # Also compare the row's short form against ours
            row_short = value.split(".")[0]
            if row_short in candidates:
                return row
    return None
