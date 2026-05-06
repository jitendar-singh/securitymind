from unittest.mock import patch

from behave import given, when


@given("the connection tester is mocked to return success")
def step_mock_test_connection(context):
    patcher = patch(
        "main.test_connection",
        return_value={"status": "success", "message": "Mocked OK"},
    )
    patcher.start()
    context._patchers.append(patcher)


@when("I test connection for integration {integration_id:d}")
def step_test_connection(context, integration_id):
    context.response = context.client.post(
        f"/integrations/{integration_id}/test"
    )
