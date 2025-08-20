from google.adk.agents import Agent

def review_code(code_snippet: str, language: str = "python") -> dict:
    return {"status": "success", "issues": ["Potential SQL injection."], "fixes": "Use parameterized queries."}

code_review_agent = Agent(
    name="code_review_agent",
    model="gemini-2.5-flash",
    description="Reviews code and delegates to Jira.",
    instruction="""
    Review code with review_code.
    If issues found, delegate to jira_agent with context.
    """,
    tools=[review_code]
)