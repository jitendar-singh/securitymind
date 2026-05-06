import os
from pathlib import Path
from unittest.mock import patch

from behave import given, when, then


def _patch_reports_base(context):
    patcher = patch("secmind.reports._BASE", context.reports_dir)
    patcher.start()
    context._patchers.append(patcher)


@given("the reports directory is isolated")
def step_isolate_reports(context):
    _patch_reports_base(context)


@given("a compliance report file exists for the current user")
def step_create_report_file(context):
    _patch_reports_base(context)
    user_dir = os.path.join(context.reports_dir, f"user_{context._current_user_id}")
    os.makedirs(user_dir, exist_ok=True)
    path = os.path.join(user_dir, "compliance_report_test_project.html")
    Path(path).write_text("<html>test report</html>")


@when("I list reports")
def step_list_reports(context):
    context.response = context.client.get("/reports")


@when('I download report "{name}"')
def step_download_report(context, name):
    context.response = context.client.get(f"/reports/{name}")


@then('the first report should have type "{report_type}"')
def step_first_report_type(context, report_type):
    data = context.response.get_json()
    assert len(data) > 0, "No reports in list"
    assert data[0]["type"] == report_type, f"Expected type '{report_type}', got '{data[0]['type']}'"
