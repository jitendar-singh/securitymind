"""
Application Security Agent - Refactored
Performs threat modeling and security architecture review.
"""

import logging
from google.adk.agents import Agent
from .threat_modeler import generate_threat_model_report
from .instruction_builder import InstructionBuilder

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Build agent instructions
instruction_builder = InstructionBuilder()
agent_instructions = instruction_builder.build_agent_instructions()


# Create the Threat Modeling Agent
threat_modeling_agent = Agent(
    name="threat_modeling_agent",
    model="gemini-2.0-flash-exp",
    description=(
        "Expert threat modeling agent specializing in threat modeling, "
        "security architecture review, and vulnerability assessment using STRIDE methodology."
    ),
    instruction=agent_instructions,
    tools=[generate_threat_model_report]
)


logger.info("Threat Modeling Agent initialized successfully")


# Export for easy import
__all__ = ["threat_modeling_agent", "generate_threat_model_report"]
