"""Notion connector — Notion API v1 with an internal-integration secret."""
from __future__ import annotations

import logging

import requests

from . import Document, DocSummary, register

logger = logging.getLogger(__name__)

_API = "https://api.notion.com/v1"
_VERSION = "2022-06-28"
_TIMEOUT = 15


def _headers(config: dict) -> dict:
    token = config.get("NOTION_TOKEN")
    if not token:
        raise ValueError("NOTION_TOKEN is required")
    return {
        "Authorization": f"Bearer {token}",
        "Notion-Version": _VERSION,
        "Content-Type": "application/json",
    }


def _title_from_page(page: dict) -> str:
    """Notion page titles live in property values keyed by various names."""
    props = page.get("properties", {}) or {}
    for prop in props.values():
        if prop.get("type") == "title":
            return "".join(t.get("plain_text", "") for t in prop.get("title", []) or []) or "(untitled)"
    return page.get("title") or "(untitled)"


def search(config: dict, query: str, max_results: int = 5) -> list[DocSummary]:
    integration_name = config.get("__integration_name", "")
    resp = requests.post(
        f"{_API}/search",
        headers=_headers(config),
        json={
            "query": query,
            "page_size": max_results,
            "filter": {"property": "object", "value": "page"},
        },
        timeout=_TIMEOUT,
    )
    resp.raise_for_status()
    out: list[DocSummary] = []
    for p in (resp.json() or {}).get("results", []):
        out.append(
            DocSummary(
                source="notion",
                integration=integration_name,
                doc_id=p.get("id", ""),
                title=_title_from_page(p),
                url=p.get("url"),
                snippet="",  # search endpoint doesn't return snippets
            )
        )
    return out


def _block_text(block: dict) -> str:
    btype = block.get("type")
    payload = block.get(btype, {}) if btype else {}
    rich = payload.get("rich_text") or payload.get("text") or []
    return "".join(rt.get("plain_text", "") for rt in rich)


def _walk_children(page_or_block_id: str, headers: dict, depth: int = 0) -> list[str]:
    if depth > 5:  # safety: deeply nested pages
        return []
    chunks: list[str] = []
    cursor = None
    while True:
        params = {"page_size": 100}
        if cursor:
            params["start_cursor"] = cursor
        resp = requests.get(
            f"{_API}/blocks/{page_or_block_id}/children",
            headers=headers,
            params=params,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json() or {}
        for block in body.get("results", []):
            text = _block_text(block)
            if text:
                chunks.append(text)
            if block.get("has_children"):
                chunks.extend(_walk_children(block["id"], headers, depth + 1))
        if not body.get("has_more"):
            break
        cursor = body.get("next_cursor")
    return chunks


def fetch(config: dict, doc_id: str) -> Document:
    integration_name = config.get("__integration_name", "")
    headers = _headers(config)
    page_resp = requests.get(f"{_API}/pages/{doc_id}", headers=headers, timeout=_TIMEOUT)
    page_resp.raise_for_status()
    page = page_resp.json() or {}
    text_chunks = _walk_children(doc_id, headers)
    return Document(
        source="notion",
        integration=integration_name,
        doc_id=doc_id,
        title=_title_from_page(page),
        url=page.get("url"),
        content="\n".join(text_chunks),
    )


register("notion", search=search, fetch=fetch)
