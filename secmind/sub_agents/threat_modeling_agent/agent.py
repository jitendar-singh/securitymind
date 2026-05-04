"""Threat Modeling Agent — multi-framework (STRIDE / ATLAS / OWASP-LLM / LINDDUN / ATT&CK)."""

import logging

from google.adk.agents import Agent

from .instruction_builder import InstructionBuilder
from .threat_modeler import generate_threat_model_report

logger = logging.getLogger(__name__)


instruction_builder = InstructionBuilder()
agent_instructions = instruction_builder.build_agent_instructions()


threat_modeling_agent = Agent(
    name="threat_modeling_agent",
    model="gemini-2.5-pro",
    description=(
        "Expert threat modeling agent. Performs security architecture review and threat "
        "modeling across multiple frameworks: STRIDE (always-on baseline), MITRE ATLAS "
        "(AI/ML systems), OWASP Top 10 for LLM (LLM-based apps), LINDDUN (privacy), and "
        "MITRE ATT&CK Enterprise (adversary mapping for cloud/infra). Frameworks are "
        "auto-detected from application details, or can be selected explicitly."
    ),
    instruction=agent_instructions,
    tools=[generate_threat_model_report],
)


logger.info("Threat Modeling Agent initialized successfully")


__all__ = ["threat_modeling_agent", "generate_threat_model_report"]
