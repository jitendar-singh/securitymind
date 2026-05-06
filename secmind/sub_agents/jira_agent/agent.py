import os
from google.adk.agents import Agent
from dotenv import load_dotenv
from atlassian import Jira
from pydantic import BaseModel


class JiraIssueRef(BaseModel):
    issue_key: str
    url: str
    status: str = "success"

load_dotenv()

jira = Jira(
    url=os.environ.get('JIRA_URL'),
    username=os.environ.get('JIRA_USERNAME'),
    password=os.environ.get('JIRA_API_TOKEN'),
    cloud=True
)

def create_jira_issue(project_key: str, summary: str, description: str, issue_type: str = 'Bug') -> dict:
    try:
        fields = {
            'project': {'key': project_key},
            'summary': summary,
            'description': description,
            'issuetype': {'name': issue_type}
        }
        issue = jira.create_issue(fields=fields)
        return {"status": "success", "issue_key": issue['key']}
    except Exception as e:
        return {"status": "error", "error_message": str(e)}

from secmind.sub_agents._scope_guard import build_scope_guard

jira_agent = Agent(
    name="jira_agent",
    model="gemini-2.5-pro",
    description=(
        "Creates Jira issues in the SECMIND project from security findings. "
        "Input: issue summary, description with findings/remediation, issue type, and priority. "
        "Output: Jira issue key and URL. "
        "Does NOT triage vulnerabilities, review code, or produce any output unrelated "
        "to Jira issue creation."
    ),
    instruction=(
        "Create issues using create_jira_issue with provided context.\n"
        "Use SECMIND as the project_key.\n"
        "Include: issue summary, detailed description (findings, recommendations, "
        "remediation steps), issue type (Bug/Task/etc.), and priority matching "
        "vulnerability urgency.\n"
        "Default issue_type is 'Bug' if not provided.\n"
        "The summary and description should be clear and actionable.\n"
        "Return the Jira issue key and URL for tracking."
        + build_scope_guard("creating Jira issues from security findings")
    ),
    tools=[create_jira_issue],
    output_schema=JiraIssueRef,
    disallow_transfer_to_parent=True,
    disallow_transfer_to_peers=True,
)