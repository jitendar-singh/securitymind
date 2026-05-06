import json

from behave import given, when, then


@given('a user exists with email "{email}" and password "{password}"')
def step_create_user(context, email, password):
    context.client.post(
        "/auth/signup",
        data=json.dumps({"email": email, "password": password, "name": "Test"}),
        content_type="application/json",
    )


@given('I am logged in as "{email}" with password "{password}"')
def step_logged_in(context, email, password):
    signup_resp = context.client.post(
        "/auth/signup",
        data=json.dumps({"email": email, "password": password, "name": "Test"}),
        content_type="application/json",
    )
    resp = context.client.post(
        "/auth/login",
        data=json.dumps({"email": email, "password": password}),
        content_type="application/json",
    )
    assert resp.status_code == 200, f"Login failed: {resp.status_code}"
    context._current_user_id = resp.get_json()["user"]["id"]


@when(u'I sign up with email "{email}" password "{password}" and name "{name}"')
def step_signup(context, email, password, name):
    context.response = context.client.post(
        "/auth/signup",
        data=json.dumps({"email": email, "password": password, "name": name}),
        content_type="application/json",
    )


@when(u'I sign up with email "{email}" password "" and name "{name}"')
def step_signup_empty_password(context, email, name):
    context.response = context.client.post(
        "/auth/signup",
        data=json.dumps({"email": email, "password": "", "name": name}),
        content_type="application/json",
    )


@when('I log in with email "{email}" and password "{password}"')
def step_login(context, email, password):
    context.response = context.client.post(
        "/auth/login",
        data=json.dumps({"email": email, "password": password}),
        content_type="application/json",
    )


@when("I request my profile")
def step_get_me(context):
    context.response = context.client.get("/auth/me")


@when("I request my profile without a session")
def step_get_me_no_session(context):
    from werkzeug.test import Client
    import main

    fresh = main.app.test_client()
    context.response = fresh.get("/auth/me")


@when("I log out")
def step_logout(context):
    context.response = context.client.post("/auth/logout")


@then("the response status should be {status:d}")
def step_check_status(context, status):
    assert context.response.status_code == status, (
        f"Expected {status}, got {context.response.status_code}: "
        f"{context.response.get_data(as_text=True)[:200]}"
    )


@then('the response JSON should have key "{key}"')
def step_json_has_key(context, key):
    data = context.response.get_json()
    assert key in data, f"Key '{key}' not in {list(data.keys())}"


@then('the response JSON at "{path}" should be "{value}"')
def step_json_value(context, path, value):
    data = context.response.get_json()
    for part in path.split("."):
        data = data[part]
    assert str(data) == value, f"Expected '{value}', got '{data}'"


@then('the response JSON at "{path}" should contain "{substr}"')
def step_json_contains(context, path, substr):
    data = context.response.get_json()
    for part in path.split("."):
        data = data[part]
    assert substr in str(data), f"'{substr}' not in '{data}'"


@then("a session cookie should be set")
def step_has_session_cookie(context):
    cookie = context.client.get_cookie("secmind_session")
    assert cookie is not None, "No secmind_session cookie set"
