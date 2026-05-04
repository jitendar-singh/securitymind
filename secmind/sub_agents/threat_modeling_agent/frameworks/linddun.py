"""LINDDUN — privacy threat model."""

from typing import Any, Dict, Optional

from .base import Framework

PRIVACY_REGULATIONS = {"gdpr", "hipaa", "ccpa", "lgpd", "pipl", "pdpa"}
PII_CLASSIFICATIONS = {"pii", "phi", "pci", "sensitive", "personal", "biometric", "health"}


class LinddunFramework(Framework):
    name = "LINDDUN"
    description = "LINDDUN privacy threat model — Linkability, Identifiability, Non-repudiation, Detectability, Disclosure of Information, Unawareness/Unintervenability, Non-compliance."
    reference_url = "https://linddun.org/"

    def __init__(self):
        self._data = self._load_data("linddun_categories.json")
        self._categories = self._data["categories"]

    def applies_to(self, app_details: Dict[str, Any]) -> bool:
        compliance = [str(c).lower() for c in (app_details.get("compliance_requirements") or [])]
        if any(r in c for c in compliance for r in PRIVACY_REGULATIONS):
            return True
        classification = [str(c).lower() for c in (app_details.get("data_classification") or [])]
        if any(p in c for c in classification for p in PII_CLASSIFICATIONS):
            return True
        data_storage = str(app_details.get("data_storage") or "").lower()
        if any(p in data_storage for p in PII_CLASSIFICATIONS):
            return True
        return False

    def build_prompt(
        self,
        app_details: Dict[str, Any],
        dfd_context: Optional[str] = None,
    ) -> str:
        details_str = self._format_app_details(app_details)
        dfd_section = self._format_dfd_section(dfd_context)
        category_lines = "\n".join(
            f"- {c['id']} {c['name']}: {c['description']}"
            for c in self._categories
        )
        return f"""You are an expert privacy engineer performing threat modeling using **LINDDUN**.

**Application Details:**
{details_str}
{dfd_section}
**LINDDUN Categories:**
{category_lines}

**Task:**
Identify privacy threats grouped by LINDDUN category. Focus on personal-data flows, retention, third-party sharing, profiling/automated-decision risks, and consent/transparency gaps. Provide compliance notes that map findings to applicable regulations (GDPR Art. references, HIPAA Privacy Rule, CCPA, etc.).

**Output Format — return ONLY valid JSON:**
{{
  "overview": "string — privacy posture summary",
  "risk_score": number (0-100),
  "identified_threats": [
    {{
      "threat": "string",
      "description": "string",
      "framework": "LINDDUN",
      "category": "Linkability | Identifiability | Non-repudiation | Detectability | Disclosure of Information | Unawareness and Unintervenability | Non-compliance",
      "technique_id": "L | I | N | D | DD | U | NC",
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "affected_components": ["string"],
      "references": ["https://linddun.org/..."],
      "cross_references": []
    }}
  ],
  "vulnerabilities": [],
  "recommendations": {{
    "data_protection": ["string — minimization, anonymization, encryption"],
    "logging_monitoring": ["string — audit + retention policies"],
    "general": ["string — consent, DSAR/erasure, DPIA"]
  }},
  "compliance_notes": ["string — map findings to GDPR/HIPAA/CCPA articles or sections"]
}}

Return ONLY the JSON object, no surrounding text.
"""
