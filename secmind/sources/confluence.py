"""Confluence connector — REST API v1 (Cloud) with basic auth (email + API token)."""
from __future__ import annotations

import logging
import re

import requests

from . import Document, DocSummary, register

logger = logging.getLogger(__name__)

_TIMEOUT = 15
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")


def _strip_html(html: str) -> str:
    text = _TAG_RE.sub(" ", html or "")
    return _WS_RE.sub(" ", text).strip()


def _base(config: dict) -> str:
    url = (config.get("CONFLUENCE_URL") or "").rstrip("/")
    if not url:
        raise ValueError("CONFLUENCE_URL is required")
    return url


def _auth(config: dict) -> tuple[str, str]:
    user = config.get("CONFLUENCE_USER")
    token = config.get("CONFLUENCE_TOKEN")
    if not user or not token:
        raise ValueError("CONFLUENCE_USER and CONFLUENCE_TOKEN are required")
    return (user, token)


def search(config: dict, query: str, max_results: int = 5) -> list[DocSummary]:
    base = _base(config)
    integration_name = config.get("__integration_name", "")
    cql = f'siteSearch ~ "{query}" AND type = "page"'
    resp = requests.get(
        f"{base}/wiki/rest/api/search",
        params={"cql": cql, "limit": max_results, "expand": "content.space"},
        auth=_auth(config),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    out: list[DocSummary] = []
    for r in (resp.json() or {}).get("results", []):
        content = r.get("content") or {}
        out.append(
            DocSummary(
                source="confluence",
                integration=integration_name,
                doc_id=str(content.get("id") or r.get("id") or ""),
                title=content.get("title") or r.get("title") or "(untitled)",
                url=f"{base}{r.get('url') or ''}" if r.get("url") else None,
                snippet=_strip_html(r.get("excerpt", ""))[:300],
            )
        )
    return out


def fetch(config: dict, doc_id: str) -> Document:
    base = _base(config)
    integration_name = config.get("__integration_name", "")
    resp = requests.get(
        f"{base}/wiki/rest/api/content/{doc_id}",
        params={"expand": "body.storage,space"},
        auth=_auth(config),
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    page = resp.json() or {}
    body_html = (page.get("body") or {}).get("storage", {}).get("value", "")
    return Document(
        source="confluence",
        integration=integration_name,
        doc_id=str(page.get("id") or doc_id),
        title=page.get("title") or "(untitled)",
        url=f"{base}/wiki{(page.get('_links') or {}).get('webui', '')}",
        content=_strip_html(body_html),
    )


register("confluence", search=search, fetch=fetch)
