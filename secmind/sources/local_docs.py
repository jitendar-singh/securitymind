"""Local-directory connector — read .md / .txt / .pdf / .docx from a path on disk."""
from __future__ import annotations

import hashlib
import logging
import os
from pathlib import Path

from . import Document, DocSummary, register

logger = logging.getLogger(__name__)

SUPPORTED_EXTS = {".md", ".txt", ".pdf", ".docx"}
_MAX_FILE_BYTES = 5 * 1024 * 1024  # 5MB cap per file to keep things sane
_SNIPPET_LEN = 280


def _root(config: dict) -> Path:
    raw = config.get("LOCAL_DOCS_PATH")
    if not raw:
        raise ValueError("LOCAL_DOCS_PATH is required")
    p = Path(raw).expanduser().resolve()
    if not p.exists() or not p.is_dir():
        raise ValueError(f"LOCAL_DOCS_PATH does not exist or is not a directory: {p}")
    return p


def _read_text(path: Path) -> str:
    if path.stat().st_size > _MAX_FILE_BYTES:
        return ""
    ext = path.suffix.lower()
    try:
        if ext in (".md", ".txt"):
            return path.read_text(encoding="utf-8", errors="replace")
        if ext == ".pdf":
            from PyPDF2 import PdfReader

            reader = PdfReader(str(path))
            return "\n".join((p.extract_text() or "") for p in reader.pages)
        if ext == ".docx":
            from docx import Document as DocxDocument

            doc = DocxDocument(str(path))
            return "\n".join(p.text for p in doc.paragraphs)
    except Exception:
        logger.exception("failed to read %s", path)
    return ""


def _doc_id_for(root: Path, path: Path) -> str:
    rel = str(path.relative_to(root))
    # Keep doc_id stable + safe (no slashes that confuse downstream URL parsing).
    return hashlib.sha1(rel.encode("utf-8")).hexdigest()[:16] + ":" + rel.replace(os.sep, "/")


def _path_from_doc_id(root: Path, doc_id: str) -> Path:
    # doc_id format: "<hash>:<relative path>"
    rel = doc_id.split(":", 1)[1] if ":" in doc_id else doc_id
    candidate = (root / rel).resolve()
    # Path-traversal guard: must stay under root.
    if not str(candidate).startswith(str(root) + os.sep) and candidate != root:
        raise ValueError(f"Refusing path outside LOCAL_DOCS_PATH: {candidate}")
    return candidate


def search(config: dict, query: str, max_results: int = 5) -> list[DocSummary]:
    root = _root(config)
    integration_name = config.get("__integration_name", "")
    needle = (query or "").lower().strip()
    if not needle:
        return []

    hits: list[tuple[int, DocSummary]] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in SUPPORTED_EXTS:
            continue
        text = _read_text(path)
        if not text:
            continue
        score = text.lower().count(needle)
        if score == 0 and needle not in path.name.lower():
            continue
        idx = text.lower().find(needle)
        snippet = text[max(0, idx - 80) : idx + _SNIPPET_LEN] if idx >= 0 else text[:_SNIPPET_LEN]
        hits.append(
            (
                score,
                DocSummary(
                    source="local_docs",
                    integration=integration_name,
                    doc_id=_doc_id_for(root, path),
                    title=path.name,
                    url=f"file://{path}",
                    snippet=snippet.strip(),
                ),
            )
        )
    hits.sort(key=lambda x: x[0], reverse=True)
    return [h[1] for h in hits[:max_results]]


def fetch(config: dict, doc_id: str) -> Document:
    root = _root(config)
    integration_name = config.get("__integration_name", "")
    path = _path_from_doc_id(root, doc_id)
    if not path.exists() or not path.is_file():
        raise ValueError(f"Document not found: {path}")
    return Document(
        source="local_docs",
        integration=integration_name,
        doc_id=doc_id,
        title=path.name,
        url=f"file://{path}",
        content=_read_text(path),
    )


register("local_docs", search=search, fetch=fetch)
