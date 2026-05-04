"""MITRE ATLAS — adversarial threats to AI/ML systems."""

from typing import Any, Dict, Optional

from .base import Framework

ML_SIGNAL_FIELDS = (
    "ml_model",
    "training_data",
    "training_data_source",
    "model_endpoint",
    "model_deployment",
    "llm_provider",
    "agent_tools",
)


class AtlasFramework(Framework):
    name = "ATLAS"
    description = "MITRE ATLAS — Adversarial Threat Landscape for AI Systems. Tactics & techniques targeting ML models, training pipelines, and agentic LLM applications."
    reference_url = "https://atlas.mitre.org/matrices/ATLAS"

    def __init__(self):
        self._data = self._load_data("atlas_techniques.json")
        self._tactics = self._data["tactics"]
        self._techniques = self._data["techniques"]

    def applies_to(self, app_details: Dict[str, Any]) -> bool:
        if any(app_details.get(f) for f in ML_SIGNAL_FIELDS):
            return True
        components = app_details.get("components", []) or []
        for c in components:
            ctype = (c.get("type") or "").lower()
            tech = (c.get("technology") or "").lower()
            if ctype in ("ml_model", "model", "llm", "vector_db", "training_pipeline"):
                return True
            if any(s in tech for s in ("openai", "anthropic", "gemini", "llama", "huggingface", "tensorflow", "pytorch", "vector")):
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
        return f"""You are an expert AI/ML security architect performing threat modeling using **MITRE ATLAS**.

**Application Details:**
{details_str}
{dfd_section}
**ATLAS Tactics:**
{tactic_lines}

**Reference Techniques (use these IDs when applicable; you may also propose other valid AML.TXXXX techniques):**
{technique_lines}

**Task:**
Identify realistic AI/ML-specific threats. For each threat, name the ATLAS tactic as `category` and provide the technique ID (e.g. `AML.T0051.001`) as `technique_id`. Cover model access, training-data poisoning, prompt injection, model extraction, jailbreaking, agent tool abuse, and impact on integrity/availability/cost as relevant.

For findings that overlap with OWASP Top 10 for LLM (e.g. ATLAS prompt injection ↔ LLM01:2025), include the OWASP ID in `cross_references`.

**Output Format — return ONLY valid JSON:**
{{
  "overview": "string — AI/ML threat surface summary for this system",
  "risk_score": number (0-100),
  "identified_threats": [
    {{
      "threat": "string",
      "description": "string",
      "framework": "ATLAS",
      "category": "ATLAS tactic name",
      "technique_id": "AML.TXXXX or AML.TXXXX.YYY",
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "affected_components": ["string"],
      "references": ["https://atlas.mitre.org/techniques/AML.TXXXX"],
      "cross_references": ["LLM0X:2025 or other framework IDs"]
    }}
  ],
  "vulnerabilities": [],
  "recommendations": {{
    "authentication": ["string"],
    "data_protection": ["string"],
    "input_validation": ["string"],
    "logging_monitoring": ["string"],
    "general": ["string — include AI-specific controls like rate-limiting inference APIs, output filtering, prompt-injection defenses"]
  }},
  "compliance_notes": null
}}

Return ONLY the JSON object, no surrounding text.
"""
