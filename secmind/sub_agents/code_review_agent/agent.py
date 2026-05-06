import json
import requests
from typing import List
from google.adk.agents import Agent

from pydantic import BaseModel

from secmind.llm import generate_json
from secmind.memory import get_memory_manager


class Issue(BaseModel):
    type: str
    description: str
    location: str

class Review(BaseModel):
    issues: List[Issue]
    fixes: List[str]
    overall_comments: str

def review_code(code_snippet: str) -> dict:
    """
    Performs a code review on the provided code snippet using Gemini AI model, with caching.
    Auto-detects the programming language.
    Focuses on code smells mentioned in the code_smells_list, readability, efficiency, security, and provides developer-like feedback.
    Supports multiple programming languages.
    """
    memory = get_memory_manager()

    cached_review = memory.get_code_review(code_snippet)
    if cached_review:
        return cached_review

    def _current_model():
        from secmind.sub_agents.code_review_agent.agent import code_review_agent
        return getattr(code_review_agent, "model", "gemini-2.5-pro")

    model = _current_model()

    detection_prompt = (
        "What programming language is this code snippet written in? "
        'Respond with JSON: {"language": "<name>"}. '
        "If it's not clear, default to Python.\n\n"
        f"```\n{code_snippet}\n```"
    )
    try:
        det_text = generate_json(detection_prompt, model, temperature=0.0)
        language = json.loads(det_text).get("language", "Python").strip().capitalize()
    except Exception:
        language = "Python"

    code_smells_list = [
        "Duplicate Code", "Long Method", "Large Class/God Class", "Long Parameter List",
        "Primitive Obsession", "Data Clumps", "Feature Envy", "Inappropriate Intimacy",
        "Middle Man", "Switch Statements", "Temporary Field", "Refused Bequest",
        "Alternative Classes with Different Interfaces", "Divergent Change",
        "Shotgun Surgery", "Parallel Inheritance Hierarchies", "Lazy Class",
        "Data Class", "Dead Code", "Speculative Generality", "Excessive Comments",
        "Improper Names", "God Object"
    ]

    prompt = f"""Act as a senior software developer with expertise in {language}. Review the following code snippet:
```
{code_snippet}
```
Provide a thorough review as if you are giving feedback in a code review session. Cover:
- Code smells: Check for any of these - {', '.join(code_smells_list)} - and any others you identify.
- Readability and maintainability: Naming conventions, structure, comments.
- Efficiency and performance: Potential bottlenecks, optimizations.
- Security issues: Vulnerabilities like injections, insecure practices.
- Best practices: Language-specific idioms, design patterns.
- Overall strengths and weaknesses.

Respond with JSON matching this schema: {{"issues": [{{"type": "...", "description": "...", "location": "..."}}], "fixes": ["..."], "overall_comments": "..."}}"""

    try:
        from secmind.llm import resolve_model_id
        model_id = resolve_model_id(model)
        raw = generate_json(
            prompt, model, temperature=0.0,
            response_schema=Review if model_id.startswith("gemini") else None,
        )
        review_data = json.loads(raw)
        if not all(key in review_data for key in ["issues", "fixes", "overall_comments"]):
            raise ValueError("Invalid response structure")

        memory.add_code_review(code_snippet, review_data)
        return review_data

    except Exception as e:
        return {
            "issues": [{"type": "Error", "description": f"Failed to generate review: {str(e)}", "location": "N/A"}],
            "fixes": [],
            "overall_comments": "An error occurred during the code review."
        }

def get_github_pr_diff(pr_url: str) -> str:
    """
    Fetches the code diff from a GitHub pull request URL.
    Expects a URL in the format 'https://github.com/{user}/{repo}/pull/{pr_number}'.
    Returns the diff content as a string.
    """
    if not pr_url.startswith('https://github.com/'):
        return "Invalid GitHub PR URL."
    diff_url = pr_url + '.diff'
    try:
        response = requests.get(diff_url)
        response.raise_for_status()
        return response.text
    except Exception as e:
        return f"Error fetching diff: {str(e)}"

# - Update the Agent configuration to include the new tool:
from secmind.sub_agents._scope_guard import build_scope_guard

code_review_agent = Agent(
    name="code_review_agent",
    model="gemini-2.5-pro",
    description=(
        "Reviews supplied code snippets or GitHub PR diffs for security vulnerabilities, "
        "code smells, readability, and best practices. "
        "Input: a code snippet (any language, auto-detected) OR a GitHub PR URL "
        "(https://github.com/owner/repo/pull/N). "
        "Output: structured Review with issues, fixes, and overall comments. "
        "Does NOT answer general programming questions, provide tutorials, "
        "draft emails, or create Jira tickets."
    ),
    instruction=(
        "You are a code review agent. Your role is to review the provided code for "
        "security vulnerabilities, code smells, readability, and efficiency.\n"
        "You receive either a direct code snippet or a GitHub pull request URL.\n"
        "If you receive a GitHub PR URL, fetch the diff using get_github_pr_diff first.\n"
        "Then, review the code using review_code.\n"
        "Explain the issues clearly and suggest fixes where possible."
        + build_scope_guard("code review of supplied code snippets or GitHub PR diffs")
    ),
    tools=[review_code, get_github_pr_diff],
    output_schema=Review,
    disallow_transfer_to_parent=True,
    disallow_transfer_to_peers=True,
)
