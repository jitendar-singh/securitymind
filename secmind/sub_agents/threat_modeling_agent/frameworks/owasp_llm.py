"""OWASP Top 10 for LLM Applications (2025)."""

from typing import Any, Dict, Optional

from .base import Framework

LLM_SIGNAL_FIELDS = (
    "llm_provider",
    "prompts",
    "agent_tools",
    "model_endpoint",
)


class OwaspLlmFramework(Framework):
    name = "OWASP-LLM"
    description = "OWASP Top 10 for LLM Applications (2025) — prompt injection, sensitive disclosure, supply chain, data/model poisoning, output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, misinformation, unbounded consumption."
    reference_url = "https://genai.owasp.org/llm-top-10/"

    def __init__(self):
        self._data = self._load_data("owasp_llm_top10.json")
        self._categories = self._data["categories"]

    def applies_to(self, app_details: Dict[str, Any]) -> bool:
        if any(app_details.get(f) for f in LLM_SIGNAL_FIELDS):
            return True
        components = app_details.get("components", []) or []
        for c in components:
            tech = (c.get("technology") or "").lower()
            ctype = (c.get("type") or "").lower()
            if ctype in ("llm", "vector_db"):
                return True
            if any(s in tech for s in ("openai", "anthropic", "gemini", "llama", "claude", "gpt", "vector")):
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
        return f"""You are an expert LLM application security reviewer using **OWASP Top 10 for LLM Applications (2025)**.

**Application Details:**
{details_str}
{dfd_section}
**OWASP LLM Categories:**
{category_lines}

**Task:**
Identify threats relevant to this LLM-based application, mapping each to one of the LLM01–LLM10 categories above. Use the OWASP ID (e.g. `LLM01:2025`) as `technique_id` and the human-readable category name as `category`. Cover prompt injection (direct + indirect via retrieved content), supply-chain risks (model hubs, third-party plugins), output handling (XSS/SSRF/SQLi from model output crossing trust boundaries), excessive agency (over-broad tool/function permissions), system prompt leakage, RAG/vector-store risks, hallucination-driven downstream failures, and resource/cost exhaustion.

For threats that overlap with MITRE ATLAS, populate `cross_references` with the matching ATLAS technique ID (e.g. `AML.T0051.000` for direct prompt injection).

**Output Format — return ONLY valid JSON:**
{{
  "overview": "string — LLM-specific risk summary",
  "risk_score": number (0-100),
  "identified_threats": [
    {{
      "threat": "string",
      "description": "string",
      "framework": "OWASP-LLM",
      "category": "Prompt Injection | Sensitive Information Disclosure | Supply Chain | Data and Model Poisoning | Improper Output Handling | Excessive Agency | System Prompt Leakage | Vector and Embedding Weaknesses | Misinformation | Unbounded Consumption",
      "technique_id": "LLM01:2025 .. LLM10:2025",
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "affected_components": ["string"],
      "references": ["https://genai.owasp.org/llmrisk/..."],
      "cross_references": ["AML.TXXXX or other framework IDs"]
    }}
  ],
  "vulnerabilities": [],
  "recommendations": {{
    "input_validation": ["string — prompt-injection defenses"],
    "data_protection": ["string"],
    "logging_monitoring": ["string"],
    "general": ["string — LLM-specific controls (output filtering, tool-use gating, rate limits, embedding access controls)"]
  }},
  "compliance_notes": null
}}

Return ONLY the JSON object, no surrounding text.
"""
