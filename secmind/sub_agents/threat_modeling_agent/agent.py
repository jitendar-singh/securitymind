"""Threat Modeling Agent — multi-framework (STRIDE / ATLAS / OWASP-LLM / LINDDUN / ATT&CK)."""

import logging

from google.adk.agents import Agent

from .instruction_builder import InstructionBuilder
from .threat_modeler import generate_threat_model_report
from secmind.sub_agents._scope_guard import build_scope_guard

logger = logging.getLogger(__name__)


instruction_builder = InstructionBuilder()
agent_instructions = instruction_builder.build_agent_instructions()


threat_modeling_agent = Agent(
    name="threat_modeling_agent",
    model="gemini-2.5-pro",
    description=(
        "Performs threat modeling across STRIDE (always-on), MITRE ATLAS (AI/ML), "
        "OWASP Top 10 for LLM (LLM apps), LINDDUN (privacy), and MITRE ATT&CK "
        "(cloud/infra). Input: application architecture details (components, data flows, "
        "deployment, compliance requirements). Output: merged HTML threat model report "
        "with per-framework risk scores and threats grouped by category. "
        "Does NOT review code, check cloud posture, draft emails, or answer general questions."
    ),
    instruction=agent_instructions + build_scope_guard(
        "threat modeling and security architecture review"
    ),
    tools=[generate_threat_model_report],
    disallow_transfer_to_parent=True,
    disallow_transfer_to_peers=True,
)


logger.info("Threat Modeling Agent initialized successfully")


__all__ = ["threat_modeling_agent", "generate_threat_model_report"]
