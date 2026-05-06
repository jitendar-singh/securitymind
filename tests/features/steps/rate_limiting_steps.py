import json

from behave import when, then


@when('I attempt to log in {n:d} times with email "{email}" and password "{password}"')
def step_rapid_logins(context, n, email, password):
    context.rate_responses = []
    for _ in range(n):
        resp = context.client.post(
            "/auth/login",
            data=json.dumps({"email": email, "password": password}),
            content_type="application/json",
        )
        context.rate_responses.append(resp)


@when('I attempt to sign up {n:d} times with email "{email}"')
def step_rapid_signups(context, n, email):
    context.rate_responses = []
    for i in range(n):
        resp = context.client.post(
            "/auth/signup",
            data=json.dumps({
                "email": f"spam-{i}@example.com",
                "password": "Secret99!",
                "name": f"Spam{i}",
            }),
            content_type="application/json",
        )
        context.rate_responses.append(resp)


@then("the first {n:d} responses should have status {status:d}")
def step_first_n_status(context, n, status):
    for i, resp in enumerate(context.rate_responses[:n]):
        assert resp.status_code == status, (
            f"Response {i+1}: expected {status}, got {resp.status_code}"
        )


@then("the first {n:d} responses should have status {s1:d} or {s2:d}")
def step_first_n_status_either(context, n, s1, s2):
    for i, resp in enumerate(context.rate_responses[:n]):
        assert resp.status_code in (s1, s2), (
            f"Response {i+1}: expected {s1} or {s2}, got {resp.status_code}"
        )


@then("the {nth} response should have status {status:d}")
def step_nth_status(context, nth, status):
    idx = _ordinal_to_index(nth)
    resp = context.rate_responses[idx]
    assert resp.status_code == status, (
        f"Response {nth}: expected {status}, got {resp.status_code}"
    )


def _ordinal_to_index(s: str) -> int:
    s = s.lower().rstrip("stndrdth")
    return int(s) - 1
