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
from .sub_agents.jira_agent.agent import jira_agent
from .sub_agents.threat_modeling_agent import threat_modeling_agent

# Load environment variables
load_dotenv()

# Configure logging
logger = logging.getLogger(__name__)


class AgentConfig:
    """Configuration for the Security Mind agent."""
    
    NAME = "secmind"
    MODEL = "gemini-2.5-flash"
    DESCRIPTION = "Master security agent that delegates tasks."
    
    # Task priorities (lower number = higher priority)
    TASK_PRIORITIES: Dict[str, int] = {
        "vulnerability_triage": 1,
        "license_checks": 1,
        "policy_reviews": 2,
        "code_reviews": 3,
        "cloud_compliance": 4,
        "application_security": 5,
        "jira_tickets": 6,
    }
    
    # Agent capabilities for user-facing information
    CAPABILITIES = [
        "Vulnerability triage and assessment",
        "Code reviews and license checks",
        "Cloud compliance checks",
        "Threat Modelling as per STRIDE",
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
        "threat_modelling": "app_sec_agent",
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
                - Application security review/Threat Modelling → app_sec_agent
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
        capabilities_list = "".join(f"- {cap}" for cap in AgentConfig.CAPABILITIES)
        
        return f"""When asked about your purpose or capabilities, respond with the below in bullet points:

                    I am Security Mind, an AI-powered Security Posture Management platform designed to enhance your organization's security throughout the software development lifecycle. By leveraging multi-agent AI architecture, I assess, monitor, and optimize your security posture—identifying vulnerabilities, ensuring compliance, and help with automating remediation workflows.

                    I can help you with the following tasks, always via delegation to the appropriate sub-agent:
                    {capabilities_list}

                    Your role is to delegate tasks to specialized agents for more efficient handling."""
    
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
        'jira_agent',
        'threat_modeling_agent'
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
        model: The AI model to use (default: gemini-2.5-flash)
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
            threat_modeling_agent,
        ]
    
    if validate and not validate_sub_agents(sub_agents):
        raise ValueError("Missing required sub-agents. Cannot create secmind agent.")
    
    logger.info(f"Creating {AgentConfig.NAME} agent with model {model}")
    
    return Agent(
        name=AgentConfig.NAME,
        model=model,
        description=AgentConfig.DESCRIPTION,
        instruction=InstructionBuilder.build_full_instruction(),
        sub_agents=sub_agents,
    )


# Create the main agent instance
secmind = create_secmind_agent()
root_agent = secmind
