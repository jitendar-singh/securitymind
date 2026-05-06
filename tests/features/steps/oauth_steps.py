from behave import when


@when('I call the OAuth callback with error "{error}"')
def step_oauth_error(context, error):
    context.response = context.client.get(f"/auth/google/callback?error={error}")


@when('I call the OAuth callback with code "{code}" and state "{state}"')
def step_oauth_state_mismatch(context, code, state):
    context.response = context.client.get(
        f"/auth/google/callback?code={code}&state={state}"
    )


@when("I call the OAuth callback with no code")
def step_oauth_no_code(context):
    context.client.set_cookie(
        "secmind_oauth_state", "valid-state", domain="localhost", path="/auth/google"
    )
    context.response = context.client.get(
        "/auth/google/callback?state=valid-state"
    )
