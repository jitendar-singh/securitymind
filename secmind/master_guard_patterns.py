"""Deterministic master-side regex guards for known off-topic failure patterns.

Checked via before_model_callback before the master LLM runs. Conservative
rules: false positives produce a refusal (cost = one extra round-trip), never
a wrong answer.
"""
import re
from typing import Optional


_EMAIL_PATTERN = re.compile(
    r"\b(draft|write|compose|send|prepare)\b.*\b(email|e-mail|message|memo|notification|letter)\b",
    re.IGNORECASE,
)

_HOWTO_PATTERN = re.compile(
    r"\bhow\s+(do|to|can|should)\s+(i|you|we)\b",
    re.IGNORECASE,
)

_CODE_OR_SECURITY_SIGNAL = re.compile(
    r"```|https?://|CVE-\d{4}-\d+",
    re.IGNORECASE,
)

_SECURITY_TASK_SIGNAL = re.compile(
    r"\b(threat\s*model|architecture|data\s*flow|stride|mitre|owasp|"
    r"security\s*(review|assessment|audit|posture|scan|check)|"
    r"compliance|vulnerabilit|firewall|endpoint|"
    r"email\s*server|message\s*(queue|broker|bus)|"
    r"smtp|amqp|rabbitmq|kafka|sqs)\b",
    re.IGNORECASE,
)

_EMAIL_REFUSAL = (
    "I cannot draft emails or messages. I only delegate to security tooling. "
    "If you need to communicate findings, please use the compliance or endpoint report tools."
)

_HOWTO_REFUSAL = (
    "This looks like a general programming or how-to question. "
    "I only delegate to security tooling (vulnerability triage, code review, "
    "cloud compliance, threat modeling, endpoint security, policy lookup, "
    "and Jira ticket creation). Please rephrase as a security task."
)


def _extract_user_text(llm_request) -> str:
    """Extract the last user turn's text from an LlmRequest."""
    for content in reversed(llm_request.contents or []):
        if content.role == "user" and content.parts:
            texts = [p.text for p in content.parts if p.text]
            if texts:
                return " ".join(texts)
    return ""


def check_refusal(llm_request) -> Optional[str]:
    """Return a refusal message if the user text matches a known off-topic
    pattern, or None to proceed normally."""
    text = _extract_user_text(llm_request)
    if not text:
        return None

    if _EMAIL_PATTERN.search(text) and not _SECURITY_TASK_SIGNAL.search(text):
        return _EMAIL_REFUSAL

    if _HOWTO_PATTERN.search(text) and not _CODE_OR_SECURITY_SIGNAL.search(text):
        return _HOWTO_REFUSAL

    return None
