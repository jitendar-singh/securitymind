"""Abstract Framework strategy contract."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, TypedDict

logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).parent.parent / "data"


class FrameworkResult(TypedDict, total=False):
    framework: str
    overview: str
    risk_score: int
    identified_threats: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    recommendations: Dict[str, List[str]]
    compliance_notes: Optional[List[str]]


class Framework(ABC):
    name: str = ""
    description: str = ""
    reference_url: str = ""

    @abstractmethod
    def applies_to(self, app_details: Dict[str, Any]) -> bool: ...

    @abstractmethod
    def build_prompt(
        self,
        app_details: Dict[str, Any],
        dfd_context: Optional[str] = None,
    ) -> str: ...

    @staticmethod
    def _format_dfd_section(dfd_context: Optional[str]) -> str:
        """Render the DFD context block, or an empty string when absent."""
        if not dfd_context:
            return ""
        return "\n\n" + dfd_context + "\n"

    def parse_response(self, raw_json: str) -> FrameworkResult:
        """Default parser: load JSON, tag threats with framework name, normalize shape."""
        data = json.loads(raw_json)

        threats = data.get("identified_threats", []) or []
        for t in threats:
            t["framework"] = self.name
            t.setdefault("technique_id", None)
            t.setdefault("affected_components", [])
            t.setdefault("references", [])
            t.setdefault("cross_references", [])

        result: FrameworkResult = {
            "framework": self.name,
            "overview": data.get("overview", ""),
            "risk_score": min(100, max(0, int(data.get("risk_score", 50)))),
            "identified_threats": threats,
            "vulnerabilities": data.get("vulnerabilities", []) or [],
            "recommendations": data.get("recommendations", {}) or {},
            "compliance_notes": data.get("compliance_notes"),
        }
        return result

    @staticmethod
    def _load_data(filename: str) -> Dict[str, Any]:
        path = DATA_DIR / filename
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _format_app_details(app_details: Dict[str, Any]) -> str:
        return json.dumps(app_details, indent=2, default=str)
