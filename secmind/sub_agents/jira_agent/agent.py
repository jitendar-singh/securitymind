import os
from google.adk.agents import Agent
from dotenv import load_dotenv
from atlassian import Jira

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

jira_agent = Agent(
    name="jira_agent",
    model="gemini-2.5-flash",
    description="Creates Jira issues from findings.",
    instruction="""
    Create issues using create_jira_issue with provided context.
    use SECMIND as the project_key.
    while creating the JIRA issue ensure that you include the following information:
    - issue summary: Describe the issue briefly.
    - issue description: Provide detailed findings and necessary context (recommendations, remediation steps).
    - issue type: Identify if this is a bug, task, etc.
    - priority : Same as the Vulnerability Urgency.
    Default issue_type is 'Bug' if not provided.
    The summary and description should be clear and actionable for the development team.
    Explain the nature of the issue, its impact, and steps for remediation.
    Ensure the output is well-structured and easy to read.
    Ensure that all relevant information is included in the Jira issue.
    At the end provide the Jira issue link or key for further tracking.
    """,
    tools=[create_jira_issue]
)