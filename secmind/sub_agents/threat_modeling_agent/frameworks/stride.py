"""STRIDE — Microsoft's classic security threat model. Always-on baseline."""

from typing import Any, Dict, Optional

from .base import Framework

STRIDE_CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]


class StrideFramework(Framework):
    name = "STRIDE"
    description = "Microsoft STRIDE — security threat model covering Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege."
    reference_url = "https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats"

    def applies_to(self, app_details: Dict[str, Any]) -> bool:
        return True

    def build_prompt(
        self,
        app_details: Dict[str, Any],
        dfd_context: Optional[str] = None,
    ) -> str:
        details_str = self._format_app_details(app_details)
        dfd_section = self._format_dfd_section(dfd_context)
        return f"""You are an expert application security architect performing threat modeling using the STRIDE methodology.

**Application Details:**
{details_str}
{dfd_section}
**STRIDE Categories:** {", ".join(STRIDE_CATEGORIES)}

**Task:**
Identify realistic, high-impact threats grouped by STRIDE category. Also surface vulnerabilities (CWE-tagged where possible), prioritized recommendations, and compliance notes.

**Output Format — return ONLY valid JSON:**
{{
  "overview": "string — application architecture and security posture summary",
  "risk_score": number (0-100),
  "identified_threats": [
    {{
      "threat": "string",
      "description": "string",
      "framework": "STRIDE",
      "category": "one of {", ".join(STRIDE_CATEGORIES)}",
      "technique_id": null,
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "affected_components": ["string"],
      "references": [],
      "cross_references": []
    }}
  ],
  "vulnerabilities": [
    {{
      "vulnerability": "string",
      "description": "string",
      "severity": "Critical|High|Medium|Low|Info",
      "component": "string",
      "cwe_id": "CWE-XXX or null",
      "remediation": "string"
    }}
  ],
  "recommendations": {{
    "authentication": ["string"],
    "authorization": ["string"],
    "data_protection": ["string"],
    "cloud_security": ["string"],
    "networking": ["string"],
    "input_validation": ["string"],
    "logging_monitoring": ["string"],
    "general": ["string"]
  }},
  "compliance_notes": ["string"] or null
}}

Return ONLY the JSON object, no surrounding text.
"""
