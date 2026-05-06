"""Policy agent — answers policy questions using configured knowledge sources.

Sources today (via configured Integrations):
- Confluence
- Notion
- Local docs directory

Plus the legacy ``./policies/`` folder that this agent has always read directly,
preserved for back-compat when no source integration is configured.
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from google.adk.agents import Agent
from dotenv import load_dotenv

from PyPDF2 import PdfReader
from docx import Document as DocxDocument

from secmind import sources

load_dotenv()

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Multi-source tools (Confluence / Notion / Local docs via integrations)
# ---------------------------------------------------------------------------


def search_policy_documents(query: str, source: Optional[str] = None) -> dict:
    """Search every configured knowledge source for documents matching the query.

    Args:
        query: Free-text search (e.g. "password rotation policy").
        source: Optional provider id to restrict the search ("confluence",
            "notion", or "local_docs"). Omit to search all configured sources.

    Returns:
        ``{"status": "success", "results": [DocSummary, ...], "count": int}``
        where each DocSummary has ``source``, ``integration``, ``doc_id``,
        ``title``, ``url`` (optional), and ``snippet``.
    """
    logger.info("Tool called: search_policy_documents(query=%r, source=%s)", query, source)
    try:
        hits = sources.search_all_sources(query, source_filter=source)
        return {
            "status": "success",
            "results": [h.to_dict() for h in hits],
            "count": len(hits),
        }
    except Exception as e:
        logger.exception("search_policy_documents failed")
        return {"status": "error", "message": str(e)}


def fetch_policy_document(source: str, integration_name: str, doc_id: str) -> dict:
    """Fetch the full plain-text content of a single document.

    Use after ``search_policy_documents`` to load the most relevant hit so you
    can quote it accurately or summarize it for the user.

    Args:
        source: Provider id ("confluence", "notion", "local_docs").
        integration_name: The integration's configured name (e.g. "main").
        doc_id: The doc_id from a search result.

    Returns:
        ``{"status": "success", "document": {source, integration, doc_id, title, url, content}}``
    """
    logger.info(
        "Tool called: fetch_policy_document(source=%s, integration=%s, doc_id=%s)",
        source, integration_name, doc_id,
    )
    try:
        doc = sources.fetch_one(source, integration_name, doc_id)
        return {"status": "success", "document": doc.to_dict()}
    except Exception as e:
        logger.exception("fetch_policy_document failed")
        return {"status": "error", "message": str(e)}


# ---------------------------------------------------------------------------
# Legacy local-policies tools (./policies directory)
#
# Kept for back-compat. If a `local_docs` integration is configured, prefer the
# multi-source tools above so the agent searches across every source uniformly.
# ---------------------------------------------------------------------------


def _legacy_policies_path() -> str:
    path = os.environ.get("POLICIES_FOLDER", "./policies/")
    os.makedirs(path, exist_ok=True)
    return os.path.abspath(path)


def list_policy_documents() -> dict:
    """List files in the legacy ./policies directory."""
    folder_path = _legacy_policies_path()
    files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
    return {"status": "success", "files": files}


def read_policy_file(policy_name: str) -> dict:
    """Read a single .txt/.pdf/.docx from the legacy ./policies directory."""
    folder_path = _legacy_policies_path()
    file_path = os.path.realpath(os.path.join(folder_path, policy_name))
    if not file_path.startswith(folder_path + os.sep) and file_path != folder_path:
        return {"status": "error", "error_message": "Access denied."}
    if not os.path.exists(file_path):
        return {"status": "error", "error_message": f"File '{policy_name}' not found."}
    ext = os.path.splitext(policy_name)[1].lower()
    try:
        if ext == ".txt":
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        elif ext == ".pdf":
            reader = PdfReader(file_path)
            content = "\n\n".join(page.extract_text() or "" for page in reader.pages)
        elif ext == ".docx":
            doc = DocxDocument(file_path)
            content = "\n\n".join(para.text for para in doc.paragraphs)
        else:
            return {"status": "error", "error_message": "Unsupported format."}
        return {"status": "success", "content": content}
    except Exception as e:
        return {"status": "error", "error_message": str(e)}


# ---------------------------------------------------------------------------
# Agent definition
# ---------------------------------------------------------------------------


_INSTRUCTION = """You are the Policy Agent. You answer policy/governance questions and summarize policy documents using the organization's configured knowledge sources.

## Tools

Cross-source (preferred):
- `search_policy_documents(query, source=None)` — search Confluence + Notion + Local docs for matching pages. Optionally pass `source="confluence"` / `"notion"` / `"local_docs"` to restrict.
- `fetch_policy_document(source, integration_name, doc_id)` — load a hit's full content so you can quote it or summarize it accurately.

Legacy (only if no source integrations exist):
- `list_policy_documents()` — list files in the local ./policies/ folder.
- `read_policy_file(policy_name)` — read a single .txt/.pdf/.docx from ./policies/.

## Workflow

1. **Search.** Call `search_policy_documents(query)` with the user's question (or its key phrase). Inspect titles + snippets to pick the most relevant hits.
2. **Fetch.** Call `fetch_policy_document(source, integration_name, doc_id)` for the top 1–3 hits. Don't guess answers from snippets alone for policy specifics.
3. **Answer.** Quote or summarize the relevant passage. Always cite the source: `[<title> · <source>]` and include the URL if present.
4. **Summarize on request.** If the user asks "summarize this document", fetch the full content and return a concise summary (key points, obligations, owners, dates) — never invent details that aren't in the document.
5. **No matches?** Say so explicitly. Do not fabricate policy content. Suggest the user check whether the relevant source integration is configured (Integrations page).

## Examples

- "What's our password rotation policy?" → search_policy_documents("password rotation"), pick the top match, fetch_policy_document(...), quote the rotation interval and cite the source.
- "Summarize the data classification policy." → search for "data classification", fetch the best hit, return a structured summary with each level + owner.
- "Which licenses are copyleft per our open source policy?" → search "open source license copyleft", fetch, quote the list.

## Constraints

- You do not have web access. Only the configured sources are available.
- Always cite. A policy answer without a source citation is not acceptable.
- Don't echo entire documents back unless the user asks. Quote or summarize.
"""


from secmind.sub_agents._scope_guard import build_scope_guard

policy_agent = Agent(
    name="policy_agent",
    model="gemini-2.5-pro",
    description=(
        "Answers policy and governance questions from configured knowledge sources "
        "(Confluence, Notion, local docs) and summarizes policy documents on demand. "
        "Input: a policy question or request to summarize a specific document. "
        "Output: answer with source citations or a structured summary. "
        "Does NOT draft emails, review code, or answer general programming questions."
    ),
    instruction=_INSTRUCTION + build_scope_guard(
        "policy and governance questions from configured knowledge sources"
    ),
    tools=[
        search_policy_documents,
        fetch_policy_document,
        list_policy_documents,
        read_policy_file,
    ],
    disallow_transfer_to_parent=True,
    disallow_transfer_to_peers=True,
)
