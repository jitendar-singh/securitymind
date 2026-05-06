import os

from behave import given, when, then


@given("I save my current session cookie")
def step_save_cookie(context):
    cookie = context.client.get_cookie("secmind_session")
    assert cookie is not None, "No secmind_session cookie to save"
    context.saved_cookies["secmind_session"] = cookie.value


@when("I restore my saved session cookie")
def step_restore_cookie(context):
    context.client.set_cookie(
        "secmind_session",
        context.saved_cookies["secmind_session"],
        domain="localhost",
    )


@given('the environment is "{env}"')
def step_set_env(context, env):
    if "SECMIND_ENV" not in context._env_backup:
        context._env_backup["SECMIND_ENV"] = os.environ.get("SECMIND_ENV")
    os.environ["SECMIND_ENV"] = env


@then("the session cookie should have the Secure flag")
def step_cookie_secure(context):
    headers = context.response.headers.getlist("Set-Cookie")
    session_header = [h for h in headers if "secmind_session" in h]
    assert session_header, f"No secmind_session Set-Cookie header. Headers: {headers}"
    assert "Secure" in session_header[0], (
        f"Secure flag missing from cookie: {session_header[0]}"
    )


@then("the session cookie should not have the Secure flag")
def step_cookie_not_secure(context):
    headers = context.response.headers.getlist("Set-Cookie")
    session_header = [h for h in headers if "secmind_session" in h]
    assert session_header, f"No secmind_session Set-Cookie header. Headers: {headers}"
    assert "Secure" not in session_header[0], (
        f"Secure flag should not be set: {session_header[0]}"
    )
