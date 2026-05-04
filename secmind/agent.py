"""
Security Mind Agent - Master security orchestration agent.

This module defines the main security agent that delegates tasks to specialized
sub-agents based on priority and task type.
"""

from typing import List, Dict, Optional
from google.adk.agents import Agent
from dotenv import load_dotenv
import logging

from .sub_agents.policy_agent.agent import policy_agent
from .sub_agents.vuln_triage_agent.agent import vuln_triage_agent
from .sub_agents.code_review_agent.agent import code_review_agent
from .sub_agents.cloud_compliance_agent.agent import cloud_compliance_agent
from .sub_agents.gcp_workload_security_agent import gcp_workload_security_agent
from .sub_agents.endpoint_security_agent import endpoint_security_agent
from .sub_agents.jira_agent.agent import jira_agent
from .sub_agents.threat_modeling_agent import threat_modeling_agent

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)


class SecMindAgent(Agent):
    """Thin subclass of ``google.adk.agents.Agent`` whose ``__module__`` lives
    in ``secmind/``. ADK's Runner infers an "implied app_name" from
    ``inspect.getmodule(root_agent.__class__).__file__``'s parent directory;
    using the bare ``Agent`` class makes that resolve to the ADK
    site-packages ``agents/`` directory, which trips a spurious app-name
    mismatch warning. Subclassing here points the heuristic at this file."""


class AgentConfig:
    """Configuration for the Security Mind agent."""
    
    NAME = "secmind"
    MODEL = "gemini-2.5-pro"
    DESCRIPTION = "Master security agent that delegates tasks."
    
    # Task priorities (lower number = higher priority)
    TASK_PRIORITIES: Dict[str, int] = {
        "vulnerability_triage": 1,
        "license_checks": 1,
        "policy_reviews": 2,
        "code_reviews": 3,
        "cloud_compliance": 4,
        "gcp_workload_security": 4,
        "endpoint_security": 4,
        "application_security": 5,
        "jira_tickets": 6,
    }

    # Agent capabilities for user-facing information
    CAPABILITIES = [
        "Vulnerability triage and assessment",
        "Code reviews and license checks",
        "Cloud compliance checks",
        "GCP workload security (GCE/GKE/Cloud Run/Cloud Functions, firewall analysis, IAM privilege escalation, container scans)",
        "Endpoint security (CrowdStrike Falcon EDR, Qualys vulnerability management)",
        "Threat Modelling across STRIDE, MITRE ATLAS, OWASP Top 10 for LLM, LINDDUN, and MITRE ATT&CK",
        "Policy interpretation",
        "Jira ticket creation",
    ]

    # Delegation mappings
    DELEGATION_MAP: Dict[str, str] = {
        "vulnerabilities": "vuln_triage_agent",
        "license_checks": "vuln_triage_agent",
        "code_reviews": "code_review_agent",
        "cloud_security": "cloud_compliance_agent",
        "cloud_compliance": "cloud_compliance_agent",
        "gcp_workload_security": "gcp_workload_security_agent",
        "firewall_analysis": "gcp_workload_security_agent",
        "container_scan": "gcp_workload_security_agent",
        "endpoint_security": "endpoint_security_agent",
        "edr": "endpoint_security_agent",
        "crowdstrike": "endpoint_security_agent",
        "qualys": "endpoint_security_agent",
        "threat_modelling": "threat_modeling_agent",
        "application_security": "app_sec_agent",
        "policy_governance": "policy_agent",
        "jira_tickets": "jira_agent",
    }


class InstructionBuilder:
    """Builds instruction prompts for the security agent."""
    
    @staticmethod
    def build_core_instruction() -> str:
        """Build the core instruction set for the agent."""
        return """You are a high-level security agent responsible for governing the security posture of an organization.
                You are trained to delegate tasks to specialized agents for more efficient handling.

                Your primary focus areas:
                - Vulnerability triage and license checks
                - Enforcing security policies
                - Reviewing code for code smells
                - Checking cloud security posture
                - Performing threat modelling

                Your primary goal is to ensure all tasks related to these aspects are handled efficiently."""
    
    @staticmethod
    def build_priority_instruction() -> str:
        """Build priority-based delegation instructions."""
        return """You will delegate tasks to specialized agents based on the priority order below:

                1. Vulnerability triage and license checks
                2. Policy reviews and summary
                3. Code reviews
                4. Cloud Security Compliance
                5. Application Security Review (e.g., Threat Modelling)
                6. Jira ticket creation when requested

                Tasks that do not fit into any of the priority segments will not be delegated.
                If an unfamiliar task is encountered, you should respond with: "I am unable to delegate that request at this time."
                All other tasks not explicitly authorized will not be delegated."""
    
    @staticmethod
    def build_delegation_rules() -> str:
        """Build specific delegation rules."""
        return """Delegation Rules:
                - Vulnerabilities and license checks → vuln_triage_agent
                - Code reviews → code_review_agent
                - Cloud security posture/compliance → cloud_compliance_agent
                - GCP workload security (GCE/GKE/Cloud Run/Cloud Functions, firewall rule analysis, IAM privilege-escalation, container vuln scans) → gcp_workload_security_agent
                - Endpoint security & vulnerability management (CrowdStrike Falcon detections/incidents/hosts, Qualys host vulnerability scans) → endpoint_security_agent
                - Application security review / Threat Modelling (STRIDE, MITRE ATLAS for AI/ML, OWASP Top 10 for LLM, LINDDUN privacy, MITRE ATT&CK) → threat_modeling_agent
                - Policy governance questions → policy_agent
                - Jira tickets → jira_agent

                Important Guidelines:
                - You will NOT provide answers directly; you will ONLY delegate
                - Only tasks explicitly authorized in your instructions should be delegated
                - When uncertain, defer to a human for clarification
                - Do not respond to topics not explicitly authorized in your instructions

                Examples:
                - When a question related to a vulnerability is encountered → delegate to vuln_triage_agent
                - When questions related to license checks are encountered → delegate to vuln_triage_agent
                - When code reviews are required → delegate to code_review_agent (lower priority)"""
    
    @staticmethod
    def build_capability_response() -> str:
        """Build the capability description for user queries."""
        return (
            "When asked about your purpose or capabilities (e.g. \"hi\", \"what can you do\", "
            "\"who are you\"), respond with EXACTLY the following markdown — no preamble, "
            "no extra prose, no other content:\n\n"
            "**Security Mind** — an AI-powered Security Posture Management platform. "
            "I orchestrate specialized sub-agents; I do not answer directly, I delegate.\n\n"
            "**Sub-agents I route to:**\n"
            "- **Vulnerability Triage Agent** — CVE triage, vulnerability assessment, license checks\n"
            "- **Code Review Agent** — code review for security smells and risky patterns\n"
            "- **Cloud Compliance Agent** — cloud posture & compliance for GCP, AWS, Azure\n"
            "- **GCP Workload Security Agent** — GCE/GKE/Cloud Run/Cloud Functions inventory, firewall risk analysis, IAM privilege-escalation, container image scans\n"
            "- **Endpoint Security Agent** — CrowdStrike Falcon (hosts, detections, incidents) and Qualys (asset vulnerability findings)\n"
            "- **Threat Modeling Agent** — threat models using STRIDE, MITRE ATLAS, OWASP LLM Top 10, LINDDUN, MITRE ATT&CK\n"
            "- **Policy Agent** — security policy interpretation and governance\n"
            "- **Jira Agent** — creates Jira tickets for findings\n\n"
            "Tell me what you need and I'll route it to the right sub-agent."
        )
    
    @classmethod
    def build_full_instruction(cls) -> str:
        """Combine all instruction components."""
        return "".join([
            cls.build_core_instruction(),
            cls.build_priority_instruction(),
            cls.build_delegation_rules(),
            cls.build_capability_response(),
        ])


def validate_sub_agents(sub_agents: List[Agent]) -> bool:
    """
    Validate that all required sub-agents are present.
    
    Args:
        sub_agents: List of sub-agents to validate
        
    Returns:
        True if all required agents are present, False otherwise
    """
    required_agents = {
        'policy_agent',
        'vuln_triage_agent',
        'code_review_agent',
        'cloud_compliance_agent',
        'gcp_workload_security_agent',
        'endpoint_security_agent',
        'jira_agent',
        'threat_modeling_agent',
    }
    agent_names = {agent.name for agent in sub_agents}
    
    missing_agents = required_agents - agent_names
    if missing_agents:
        logger.warning(f"Missing required sub-agents: {missing_agents}")
        return False
    
    return True


def create_secmind_agent(
    model: str = AgentConfig.MODEL,
    sub_agents: Optional[List[Agent]] = None,
    validate: bool = True
) -> Agent:
    """
    Create and configure the Security Mind master agent.
    
    Args:
        model: The AI model to use (default: gemini-2.5-pro)
        sub_agents: List of sub-agents to delegate to (optional)
        validate: Whether to validate sub-agents before creating agent
    
    Returns:
        Configured Agent instance
        
    Raises:
        ValueError: If validation is enabled and required sub-agents are missing
    """
    if sub_agents is None:
        sub_agents = [
            policy_agent,
            vuln_triage_agent,
            code_review_agent,
            jira_agent,
            cloud_compliance_agent,
            gcp_workload_security_agent,
            endpoint_security_agent,
            threat_modeling_agent,
        ]
    
    if validate and not validate_sub_agents(sub_agents):
        raise ValueError("Missing required sub-agents. Cannot create secmind agent.")
    
    logger.info(f"Creating {AgentConfig.NAME} agent with model {model}")
    
    return SecMindAgent(
        name=AgentConfig.NAME,
        model=model,
        description=AgentConfig.DESCRIPTION,
        instruction=InstructionBuilder.build_full_instruction(),
        sub_agents=sub_agents,
    )


# Create the main agent instance
secmind = create_secmind_agent()
root_agent = secmind
