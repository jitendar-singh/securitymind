import os
from google.adk.agents import Agent
from dotenv import load_dotenv
from atlassian import Jira

load_dotenv()

jira = Jira(
    url=os.environ.get('JIRA_URL'),
    username=os.environ.get('JIRA_USER'),
    password=os.environ.get('JIRA_TOKEN'),
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
    Ask for project_key if missing.
    """,
    tools=[create_jira_issue]
)