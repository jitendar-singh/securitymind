"""
Security Mind Agent - Master security orchestration agent.

This module defines the main security agent that delegates tasks to specialized
sub-agents based on priority and task type.
"""

from typing import List, Dict, Optional
from google.adk.agents import Agent
from google.adk.tools.agent_tool import AgentTool
from google.genai import types as genai_types
from dotenv import load_dotenv
import logging

from .master_guard_patterns import check_refusal

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

    # Routing is now handled by worker tool descriptions (AgentTool).
    # DELEGATION_MAP removed — tool descriptions are the single source of truth.


class InstructionBuilder:
    """Builds instruction prompts for the security agent."""
    
    @staticmethod
    def build_core_instruction() -> str:
        """Build the core instruction set for the agent."""
        return """You are the Security Mind orchestrator. You call specialized worker tools to gather security information and produce typed results, then write the user-facing reply yourself.

You NEVER hand off the conversation. You always own the user channel. Workers are tools you invoke with a bounded task — they run, return a result, and terminate.

Your security focus areas:
- Vulnerability triage and license checks
- Security policy governance
- Code review for security smells
- Cloud security posture assessment
- GCP workload security analysis
- Endpoint security (CrowdStrike Falcon, Qualys)
- Threat modeling (STRIDE, MITRE ATLAS, OWASP LLM, LINDDUN, MITRE ATT&CK)
- Jira ticket creation for findings

"""
    
    @staticmethod
    def build_priority_instruction() -> str:
        """Build priority-based delegation instructions."""
        return """When multiple worker tools could match a request, prefer this priority order:
1. Vulnerability triage and license checks (vuln_triage_agent)
2. Policy reviews and summary (policy_agent)
3. Code reviews (code_review_agent)
4. Cloud security compliance (cloud_compliance_agent)
5. GCP workload security (gcp_workload_security_agent)
6. Endpoint security (endpoint_security_agent)
7. Threat modeling (threat_modeling_agent)
8. Jira ticket creation (jira_agent)

If no worker tool's description matches the request, reply with: "I am unable to delegate that request at this time."

"""
    
    @staticmethod
    def build_delegation_rules() -> str:
        """Build routing rules for the orchestrator."""
        return """ROUTING RULES:
- Each user turn is routed from scratch. A "yes"/"do it"/"continue" only counts if your previous turn was a confirmation question you wrote yourself.
- Read each worker tool's description to decide routing. Do not invent capabilities not described in a tool's description.
- If no worker tool's description matches the request, reply with: "I am unable to delegate that request at this time." Do not improvise.
- You may chain multiple worker calls in sequence (e.g., code_review_agent then jira_agent) when the user's request spans multiple tools.
- After a worker returns, synthesize the result into a user-friendly reply. Do not paste raw JSON to the user.
- If a worker returns {"status": "out_of_scope", ...}, do not retry. Tell the user the request is outside the system's capabilities.
- Do NOT draft emails, answer general programming questions, or produce content unrelated to security tooling.

"""
    
    @staticmethod
    def build_capability_response() -> str:
        """Build the capability description for user queries."""
        return (
            "When asked about your purpose or capabilities (e.g. \"hi\", \"what can you do\", "
            "\"who are you\"), respond with EXACTLY the following markdown — no preamble, "
            "no extra prose, no other content:\n\n"
            "**Security Mind** — an AI-powered Security Posture Management platform. "
            "I orchestrate specialized worker tools to handle security tasks.\n\n"
            "**Worker tools I use:**\n"
            "- **Vulnerability Triage Agent** — CVE triage, vulnerability assessment, license checks\n"
            "- **Code Review Agent** — code review for security smells and risky patterns\n"
            "- **Cloud Compliance Agent** — cloud posture & compliance for GCP, AWS, Azure\n"
            "- **GCP Workload Security Agent** — GCE/GKE/Cloud Run/Cloud Functions inventory, firewall risk analysis, IAM privilege-escalation, container image scans\n"
            "- **Endpoint Security Agent** — CrowdStrike Falcon (hosts, detections, incidents) and Qualys (asset vulnerability findings)\n"
            "- **Threat Modeling Agent** — threat models using STRIDE, MITRE ATLAS, OWASP LLM Top 10, LINDDUN, MITRE ATT&CK\n"
            "- **Policy Agent** — security policy interpretation and governance\n"
            "- **Jira Agent** — creates Jira tickets for findings\n\n"
            "Tell me what you need and I'll use the right tool to handle it."
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


def master_before_model_callback(callback_context, llm_request):
    """Deterministic guard: short-circuit known off-topic patterns before the LLM runs."""
    refusal = check_refusal(llm_request)
    if refusal is not None:
        from google.adk.models.llm_response import LlmResponse
        return LlmResponse(
            content=genai_types.Content(
                role="model",
                parts=[genai_types.Part(text=refusal)],
            )
        )
    return None


def validate_worker_tools(worker_tools: list) -> bool:
    """Validate that all required worker agents are present as AgentTools."""
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
    tool_names = {t.agent.name for t in worker_tools if hasattr(t, 'agent')}

    missing = required_agents - tool_names
    if missing:
        logger.warning(f"Missing required worker tools: {missing}")
        return False

    return True


def create_secmind_agent(
    model: str = AgentConfig.MODEL,
    validate: bool = True
) -> Agent:
    """
    Create and configure the Security Mind master agent.

    The master uses AgentTool wrappers (orchestrator pattern) instead of
    sub_agents handoff. Workers are invoked as tools and never own the
    user-facing conversation.
    """
    worker_tools = [
        AgentTool(agent=policy_agent),
        AgentTool(agent=vuln_triage_agent),
        AgentTool(agent=code_review_agent),
        AgentTool(agent=jira_agent),
        AgentTool(agent=cloud_compliance_agent),
        AgentTool(agent=gcp_workload_security_agent),
        AgentTool(agent=endpoint_security_agent),
        AgentTool(agent=threat_modeling_agent),
    ]

    if validate and not validate_worker_tools(worker_tools):
        raise ValueError("Missing required worker tools. Cannot create secmind agent.")

    logger.info(f"Creating {AgentConfig.NAME} agent with model {model}")

    return SecMindAgent(
        name=AgentConfig.NAME,
        model=model,
        description=AgentConfig.DESCRIPTION,
        instruction=InstructionBuilder.build_full_instruction(),
        tools=worker_tools,
        before_model_callback=master_before_model_callback,
    )


# Create the main agent instance
secmind = create_secmind_agent()
root_agent = secmind
