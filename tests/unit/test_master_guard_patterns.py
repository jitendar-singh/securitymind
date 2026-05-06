from types import SimpleNamespace

import pytest

from secmind.master_guard_patterns import (
    _extract_user_text,
    check_refusal,
    _EMAIL_REFUSAL,
    _HOWTO_REFUSAL,
)


def _make_request(text: str, role: str = "user"):
    part = SimpleNamespace(text=text)
    content = SimpleNamespace(role=role, parts=[part])
    return SimpleNamespace(contents=[content])


class TestExtractUserText:
    def test_extracts_last_user_turn(self):
        model_turn = SimpleNamespace(role="model", parts=[SimpleNamespace(text="hi")])
        user_turn = SimpleNamespace(role="user", parts=[SimpleNamespace(text="hello")])
        req = SimpleNamespace(contents=[model_turn, user_turn])
        assert _extract_user_text(req) == "hello"

    def test_ignores_model_turns(self):
        model_turn = SimpleNamespace(role="model", parts=[SimpleNamespace(text="only model")])
        req = SimpleNamespace(contents=[model_turn])
        assert _extract_user_text(req) == ""

    def test_empty_contents(self):
        req = SimpleNamespace(contents=[])
        assert _extract_user_text(req) == ""

    def test_none_contents(self):
        req = SimpleNamespace(contents=None)
        assert _extract_user_text(req) == ""

    def test_joins_multiple_parts(self):
        parts = [SimpleNamespace(text="part1"), SimpleNamespace(text="part2")]
        content = SimpleNamespace(role="user", parts=parts)
        req = SimpleNamespace(contents=[content])
        assert _extract_user_text(req) == "part1 part2"


class TestCheckRefusal:
    def test_email_pattern_triggers_refusal(self):
        req = _make_request("write an email to Bob about the meeting")
        assert check_refusal(req) == _EMAIL_REFUSAL

    def test_email_with_security_signal_passes(self):
        req = _make_request("write an email server threat model")
        assert check_refusal(req) is None

    def test_howto_pattern_triggers_refusal(self):
        req = _make_request("how do I sort a list in Python")
        assert check_refusal(req) == _HOWTO_REFUSAL

    def test_howto_with_cve_signal_passes(self):
        req = _make_request("how do I fix CVE-2024-1234")
        assert check_refusal(req) is None

    def test_howto_with_code_block_passes(self):
        req = _make_request("how do I fix this ```python\nprint('x')```")
        assert check_refusal(req) is None

    def test_howto_with_url_passes(self):
        req = _make_request("how can I review https://github.com/org/repo/pull/1")
        assert check_refusal(req) is None

    def test_security_task_passes(self):
        req = _make_request("run a security assessment on my GCP project")
        assert check_refusal(req) is None

    def test_empty_text_passes(self):
        req = SimpleNamespace(contents=[])
        assert check_refusal(req) is None

    def test_compose_message_triggers_refusal(self):
        req = _make_request("compose a message to the team about deadlines")
        assert check_refusal(req) == _EMAIL_REFUSAL

    def test_draft_email_about_smtp_passes(self):
        req = _make_request("draft email about smtp server vulnerabilities")
        assert check_refusal(req) is None
