import json

import main
from behave import when


@when("I get model settings")
def step_get_settings(context):
    context.response = context.client.get("/settings/models")


@when('I set model for agent "{agent}" to "{model}"')
def step_set_model(context, agent, model):
    context.response = context.client.put(
        "/settings/models",
        data=json.dumps({"selections": {agent: model}}),
        content_type="application/json",
    )


@when("I get model settings without a session")
def step_get_settings_no_auth(context):
    fresh = main.app.test_client()
    context.response = fresh.get("/settings/models")


@when("I update model settings without a session")
def step_put_settings_no_auth(context):
    fresh = main.app.test_client()
    context.response = fresh.put(
        "/settings/models",
        data=json.dumps({"selections": {"secmind": "gemini-2.5-flash"}}),
        content_type="application/json",
    )
