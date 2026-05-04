"""
Source connectors for the policy agent.

Each connector module exposes two callables:

    search(integration_config: dict, query: str, max_results: int) -> list[DocSummary]
    fetch(integration_config: dict, doc_id: str) -> Document

Connectors are registered in REGISTRY by integration provider id (e.g.
"confluence", "notion", "local_docs"). The policy agent calls
``search_all_sources`` / ``fetch_one`` here, which walk active integrations
from the IntegrationStore and dispatch to the right connector.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Callable, Optional

from secmind.integration_store import get_store
from secmind.user_context import current_user_id

logger = logging.getLogger(__name__)


@dataclass
class DocSummary:
    source: str          # integration provider id, e.g. "confluence"
    integration: str     # integration name (e.g. "main")
    doc_id: str
    title: str
    url: Optional[str] = None
    snippet: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Document:
    source: str
    integration: str
    doc_id: str
    title: str
    url: Optional[str] = None
    content: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


SearchFn = Callable[[dict, str, int], list[DocSummary]]
FetchFn = Callable[[dict, str], Document]

# Lazy registration — modules import secmind.sources and register themselves.
REGISTRY: dict[str, dict[str, Callable]] = {}


def register(provider_id: str, *, search: SearchFn, fetch: FetchFn) -> None:
    REGISTRY[provider_id] = {"search": search, "fetch": fetch}


def _ensure_loaded() -> None:
    """Import all built-in connectors so they self-register."""
    from . import confluence, notion, local_docs  # noqa: F401


def configured_sources() -> list[dict]:
    """Active integrations (for the current request's user) whose provider
    has a registered connector."""
    _ensure_loaded()
    uid = current_user_id()
    if uid is None:
        return []
    out = []
    for rec in get_store().iter_active(uid):
        if rec["provider"] in REGISTRY:
            out.append(rec)
    return out


def search_all_sources(
    query: str,
    max_results_per_source: int = 5,
    source_filter: Optional[str] = None,
) -> list[DocSummary]:
    """Search every active integration that has a registered connector.

    Args:
        query: Free-text search query.
        max_results_per_source: Cap per integration to avoid one source flooding.
        source_filter: Optional provider id to restrict the search to (e.g. "confluence").
    """
    _ensure_loaded()
    results: list[DocSummary] = []
    for rec in configured_sources():
        if source_filter and rec["provider"] != source_filter:
            continue
        connector = REGISTRY[rec["provider"]]
        try:
            cfg = {**rec["config"], "__integration_name": rec["name"]}
            hits = connector["search"](cfg, query, max_results_per_source)
            results.extend(hits or [])
        except Exception:
            logger.exception(
                "search failed for %s/%s", rec["provider"], rec["name"]
            )
    return results


def fetch_one(source: str, integration_name: str, doc_id: str) -> Document:
    """Fetch a single document from a specific integration."""
    _ensure_loaded()
    connector = REGISTRY.get(source)
    if connector is None:
        raise ValueError(f"No connector registered for source '{source}'")
    uid = current_user_id()
    if uid is None:
        raise ValueError("No user in context — cannot resolve integrations")
    for rec in get_store().iter_active(uid):
        if rec["provider"] == source and rec["name"] == integration_name:
            cfg = {**rec["config"], "__integration_name": rec["name"]}
            return connector["fetch"](cfg, doc_id)
    raise ValueError(f"No active integration '{source}/{integration_name}' configured")
