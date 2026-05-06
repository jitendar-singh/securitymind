"""Shared scope-contract instruction block for all worker agents."""


def build_scope_guard(scope_description: str) -> str:
    return f"""

SCOPE CONTRACT:
Your scope is limited to: {scope_description}.
If the task you receive is outside this scope, do not attempt it.
Return {{"status": "out_of_scope", "reason": "<why>"}} and stop.
Do not draft, summarize, or reformat content that is not a direct product of your tools.
Do not answer general programming questions, draft emails, or produce any output unrelated to your tools.
"""
