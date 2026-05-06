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
from secmind.sub_agents._scope_guard import build_scope_guard

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)
# ============================================================================
# Search Agent
# ============================================================================


search_agent = Agent(
    model='gemini-2.5-pro',
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
    model="gemini-2.5-pro",
    description=(
        "Triages CVE vulnerabilities (NVD + cve.org lookup, CVSS scoring, patch priority), "
        "checks software package licenses across PyPI/NPM/Maven with automatic ecosystem "
        "detection, and parses CycloneDX/SPDX SBOMs for license compliance. "
        "Input: CVE IDs, package names, or SBOM JSON content. "
        "Output: severity assessments, license identifiers, or SBOM compliance summaries. "
        "Does NOT review code, check cloud posture, draft emails, or answer general "
        "programming questions."
    ),
    instruction=InstructionBuilder.build_full_instruction() + build_scope_guard(
        "vulnerability triage, license checking, and SBOM parsing"
    ),
    tools=[agent_tool.AgentTool(agent=search_agent),
        triage_vulnerability,
        check_package_license,
        parse_sbom,
    ],
    disallow_transfer_to_parent=True,
    disallow_transfer_to_peers=True,
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
