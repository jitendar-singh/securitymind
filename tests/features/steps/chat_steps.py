import json

from behave import when


@when('I send a chat message "{message}"')
def step_send_chat(context, message):
    context.response = context.client.post(
        "/chat",
        data=json.dumps({"message": message}),
        content_type="application/json",
    )


@when('I send a chat message ""')
def step_send_chat_empty(context):
    context.response = context.client.post(
        "/chat",
        data=json.dumps({"message": ""}),
        content_type="application/json",
    )


@when('I send a chat message "{message}" without a session')
def step_send_chat_no_session(context, message):
    import main

    fresh = main.app.test_client()
    context.response = fresh.post(
        "/chat",
        data=json.dumps({"message": message}),
        content_type="application/json",
    )
