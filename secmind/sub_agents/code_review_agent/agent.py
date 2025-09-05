import os
import json
import requests
from typing import List
from google.adk.agents import Agent
import google.generativeai as genai

from pydantic import BaseModel


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
    Performs a code review on the provided code snippet using Gemini AI model.
    Auto-detects the programming language.
    Focuses on code smells mentioned in the code_smells_list, readability, efficiency, security, and provides developer-like feedback.
    Supports multiple programming languages.
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    if not api_key:
        return {"issues": [], "fixes": [], "overall_comments": "Google API key not set."}
    
    genai.configure(api_key=api_key)
    
    model = genai.GenerativeModel(
        'gemini-2.5-flash', 
    )
    
    # Step 1: Auto-detect the language
    detection_prompt = f"""
    What programming language is this code snippet written in? Respond with only the language name (e.g., 'Python', 'JavaScript'). If it's not clear, default to 'Python'.

    ```
    {code_snippet}
    ```
    """
    try:
        detection_response = model.generate_content(detection_prompt)
        language = detection_response.text.strip().lower().capitalize()
    except Exception:
        language = "Python"  # Fallback
    
    code_smells_list = [
        "Duplicate Code", "Long Method", "Large Class/God Class", "Long Parameter List",
        "Primitive Obsession", "Data Clumps", "Feature Envy", "Inappropriate Intimacy",
        "Middle Man", "Switch Statements", "Temporary Field", "Refused Bequest",
        "Alternative Classes with Different Interfaces", "Divergent Change",
        "Shotgun Surgery", "Parallel Inheritance Hierarchies", "Lazy Class",
        "Data Class", "Dead Code", "Speculative Generality", "Excessive Comments",
        "Improper Names", "God Object"
    ]
    
    prompt = f"""
            Act as a senior software developer with expertise in {language}. Review the following code snippet:
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

            Respond strictly with the structured output defined by the schema.
        """
    
    try:
        response = model.generate_content(
            prompt,
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
                response_schema=Review,  # Enforces the structure
                temperature=0.0  # Increase determinism for structured output
            )
        )
        
        # Try to use parsed if available
        try:
            review_data = response.parsed.dict()
        except AttributeError:
            # Fallback to parsing text if schema enforcement fails
            json_str = response.text.strip()
            if json_str.startswith('```json'):
                json_str = json_str.split('```json')[1].split('```')[0].strip()
            elif json_str.startswith('```'):
                json_str = json_str[3:-3].strip()
            review_data = json.loads(json_str)
            # Basic validation
            if not all(key in review_data for key in ["issues", "fixes", "overall_comments"]):
                raise ValueError("Invalid response structure after fallback")
        
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
code_review_agent = Agent(
    name="code_review_agent",
    model="gemini-2.5-flash",
    description="Reviews code for security,code smells and best practices.And delegates to jira_agent if issues found.",
    instruction="""You are a code review agent. Your role is to review the provided code for security vulnerabilities, code smells, readability, and efficiency.
        The user can provide either a direct code snippet or a GitHub pull request URL. Your goal is to provide a thorough review and suggest necessary fixes.
        If the user provides a GitHub pull request URL, fetch the diff using get_github_pr_diff first.
        Then, review the code using review_code.
        Make sure to explain the issues clearly and suggest fixes where possible.
        """,
    tools=[review_code, get_github_pr_diff]
)
