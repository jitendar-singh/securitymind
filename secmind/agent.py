from google.adk.agents import Agent
from .sub_agents.policy_agent.agent import policy_agent
from .sub_agents.vuln_triage_agent.agent import vuln_triage_agent
from .sub_agents.code_review_agent.agent import code_review_agent
from .sub_agents.jira_agent.agent import jira_agent

secmind = Agent(
    name="secmind",
    model="gemini-2.5-flash",
    description="Master security agent that delegates tasks.",
    instruction="""
    Delegate tasks only:
    - Policy questions to policy_agent (local/Confluence).
    - Vulnerability triage and license checks to vuln_triage_agent.
    - Code review to code_review_agent (may delegate to jira_agent).
    Do not answer directly.
    """,
    sub_agents=[policy_agent, vuln_triage_agent, code_review_agent, jira_agent],
)
root_agent = secmind