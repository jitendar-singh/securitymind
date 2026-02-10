"""
Vulnerability Triage Agent - Refactored Version

This module defines the vulnerability triage agent with improved structure,
error handling, logging, and maintainability.

Author: Security Mind Team
Version: 2.0.3 (Fixed Tool Mixing Error)
"""

import logging
from google.adk.agents import Agent
from google.adk.tools import google_search, agent_tool
from dotenv import load_dotenv

# Import refactored modules
from .constants import COPYLEFT_LICENSES
from .vulnerability_triage import triage_vulnerability
from .license_checker import check_package_license
from .sbom_parser import parse_sbom
from .instruction_builder import InstructionBuilder

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
# ============================================================================
# Search Agent
# ============================================================================


search_agent = Agent(
    model='gemini-2.5-flash',
    name='SearchAgent',
    instruction="""
    You're a specialist in Google Search
    """,
    tools=[google_search],
)

# ============================================================================
# Main Vulnerability Triage Agent
# ============================================================================

vuln_triage_agent = Agent(
    name="vuln_triage_agent",
    model="gemini-2.5-flash",
    description=(
        "Triages vulnerabilities and verifies software package licenses "
        "across multiple ecosystems, with SBOM parsing support. "
        "Automatically detects ecosystems and searches web for unknown licenses."
    ),
    instruction=InstructionBuilder.build_full_instruction(),
    tools=[agent_tool.AgentTool(agent=search_agent),
        triage_vulnerability,
        check_package_license,
        parse_sbom,
    ]
)

# ============================================================================
# Public API
# ============================================================================

__all__ = [
    'vuln_triage_agent',
    'triage_vulnerability',
    'check_package_license',
    'parse_sbom',
    'COPYLEFT_LICENSES',
]


# ============================================================================
# Module Initialization
# ============================================================================

logger.info("Vulnerability Triage Agent initialized successfully")
logger.info(f"Supported ecosystems: PyPI, NPM, Maven (auto-detected)")
logger.info(f"SBOM formats: CycloneDX, SPDX")
logger.info(f"License search: Automatic via web search")
