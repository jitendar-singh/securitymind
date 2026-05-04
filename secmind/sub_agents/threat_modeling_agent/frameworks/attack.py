"""MITRE ATT&CK Enterprise — adversary tactics & techniques on traditional/cloud infra."""

from typing import Any, Dict, Optional

from .base import Framework


class AttackFramework(Framework):
    name = "ATT&CK"
    description = "MITRE ATT&CK Enterprise — adversary tactics and techniques observed against enterprise and cloud infrastructure. Layers operational adversary mapping on top of architectural threat modeling."
    reference_url = "https://attack.mitre.org/matrices/enterprise/"

    def __init__(self):
        self._data = self._load_data("attack_techniques.json")
        self._tactics = self._data["tactics"]
        self._techniques = self._data["techniques"]

    def applies_to(self, app_details: Dict[str, Any]) -> bool:
        if app_details.get("cloud_provider") or app_details.get("deployment_env"):
            return True
        if app_details.get("networking") or app_details.get("cloud_config"):
            return True
        return False

    def build_prompt(
        self,
        app_details: Dict[str, Any],
        dfd_context: Optional[str] = None,
    ) -> str:
        details_str = self._format_app_details(app_details)
        dfd_section = self._format_dfd_section(dfd_context)
        tactic_lines = "\n".join(f"- {t['id']}: {t['name']}" for t in self._tactics)
        technique_lines = "\n".join(
            f"- {tid}: {meta['name']} (tactic: {meta['tactic']})"
            for tid, meta in self._techniques.items()
        )
        return f"""You are an expert adversary emulation engineer performing threat modeling using **MITRE ATT&CK Enterprise**.

**Application Details:**
{details_str}
{dfd_section}
**ATT&CK Tactics:**
{tactic_lines}

**Reference Techniques (use these IDs when applicable; you may also propose other valid TXXXX techniques):**
{technique_lines}

**Task:**
Identify likely adversary behaviors against this system. For each threat, the ATT&CK tactic name goes in `category` and the technique ID (e.g. `T1190`, `T1078.004`) in `technique_id`. Prioritize cloud-resident techniques where the system runs in cloud/Kubernetes, and remote-services / public-facing techniques where applicable.

**Output Format — return ONLY valid JSON:**
{{
  "overview": "string — adversary-facing risk summary mapped to ATT&CK",
  "risk_score": number (0-100),
  "identified_threats": [
    {{
      "threat": "string",
      "description": "string",
      "framework": "ATT&CK",
      "category": "ATT&CK tactic name",
      "technique_id": "TXXXX or TXXXX.YYY",
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "affected_components": ["string"],
      "references": ["https://attack.mitre.org/techniques/TXXXX"],
      "cross_references": []
    }}
  ],
  "vulnerabilities": [],
  "recommendations": {{
    "authentication": ["string"],
    "cloud_security": ["string"],
    "networking": ["string"],
    "logging_monitoring": ["string — detection guidance per ATT&CK data sources"],
    "general": ["string"]
  }},
  "compliance_notes": null
}}

Return ONLY the JSON object, no surrounding text.
"""
