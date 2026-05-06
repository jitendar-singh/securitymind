import json

from behave import given, when, then


def _table_to_dict(table):
    return {row["key"]: row["value"] for row in table if row["key"]}


@given('I have created an integration with provider "{provider}" and name "{name}"')
def step_create_default_integration(context, provider, name):
    config = {"API_KEY": "test-key-123"}
    resp = context.client.post(
        "/integrations",
        data=json.dumps({"provider": provider, "name": name, "config": config}),
        content_type="application/json",
    )
    assert resp.status_code == 201, f"Setup failed: {resp.status_code} {resp.get_data(as_text=True)}"


@when('I create an integration with provider "{provider}" name "{name}" and config:')
def step_create_integration(context, provider, name):
    config = _table_to_dict(context.table)
    context.response = context.client.post(
        "/integrations",
        data=json.dumps({"provider": provider, "name": name, "config": config}),
        content_type="application/json",
    )


@when("I create an integration with empty provider and name")
def step_create_integration_empty(context):
    context.response = context.client.post(
        "/integrations",
        data=json.dumps({"provider": "", "name": "", "config": {}}),
        content_type="application/json",
    )


@when("I list my integrations")
def step_list_integrations(context):
    context.response = context.client.get("/integrations")


@when("I get integration {integration_id:d}")
def step_get_integration(context, integration_id):
    context.response = context.client.get(f"/integrations/{integration_id}")


@when('I update integration {integration_id:d} with name "{name}"')
def step_update_integration(context, integration_id, name):
    context.response = context.client.put(
        f"/integrations/{integration_id}",
        data=json.dumps({"name": name}),
        content_type="application/json",
    )


@when("I delete integration {integration_id:d}")
def step_delete_integration(context, integration_id):
    context.response = context.client.delete(f"/integrations/{integration_id}")


@when('I sign up and log in as "{email}" with password "{password}"')
def step_signup_and_login(context, email, password):
    context.client.post(
        "/auth/signup",
        data=json.dumps({"email": email, "password": password, "name": "Test"}),
        content_type="application/json",
    )
    resp = context.client.post(
        "/auth/login",
        data=json.dumps({"email": email, "password": password}),
        content_type="application/json",
    )
    assert resp.status_code == 200


@then('the response JSON should not have key "{key}"')
def step_json_not_have_key(context, key):
    data = context.response.get_json()
    assert key not in data, f"Key '{key}' should not be in response but found: {data.get(key)}"


@then("the response should be a list of length {n:d}")
def step_json_list_length(context, n):
    data = context.response.get_json()
    assert isinstance(data, list), f"Expected list, got {type(data).__name__}"
    assert len(data) == n, f"Expected {n} items, got {len(data)}"
