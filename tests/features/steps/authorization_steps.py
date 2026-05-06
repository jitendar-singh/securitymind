import main
from behave import when


@when('I make an unauthenticated GET to "{path}"')
def step_unauth_get(context, path):
    fresh = main.app.test_client()
    context.response = fresh.get(path)


@when('I make an unauthenticated POST to "{path}"')
def step_unauth_post(context, path):
    fresh = main.app.test_client()
    context.response = fresh.post(path)


@when('I make an unauthenticated PUT to "{path}"')
def step_unauth_put(context, path):
    fresh = main.app.test_client()
    context.response = fresh.put(path)


@when('I make an unauthenticated DELETE to "{path}"')
def step_unauth_delete(context, path):
    fresh = main.app.test_client()
    context.response = fresh.delete(path)
