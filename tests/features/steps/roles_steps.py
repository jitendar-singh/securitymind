import json
from datetime import datetime, timezone

from behave import given
from secmind.integration_store import get_store


@given("orphan integrations exist in the store")
def step_create_orphan(context):
    store = get_store()
    now = datetime.now(timezone.utc).isoformat()
    config_blob = store._encrypt({"JIRA_TOKEN": "orphan-token"})
    store._conn.execute(
        """
        INSERT INTO integrations
            (user_id, provider, name, enabled, config_encrypted, created_at, updated_at)
        VALUES (0, 'jira', 'orphan', 1, ?, ?, ?)
        """,
        (config_blob, now, now),
    )
    store._conn.commit()
