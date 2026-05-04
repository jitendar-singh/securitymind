"""
Per-provider integration connection tests.

Each tester takes a decrypted config dict and returns
``{"status": "success" | "error", "message": str}``. All checks are read-only.

Imports inside each tester are lazy so the module stays importable even when
optional SDKs (boto3, etc.) aren't installed.
"""
from __future__ import annotations

import logging
import os
from typing import Callable

logger = logging.getLogger(__name__)

Tester = Callable[[dict], dict]

_HTTP_TIMEOUT = 10


def _missing(config: dict, *keys: str) -> str | None:
    missing = [k for k in keys if not config.get(k)]
    return f"Missing required field(s): {', '.join(missing)}" if missing else None


def test_gemini(config: dict) -> dict:
    err = _missing(config, "GOOGLE_API_KEY")
    if err:
        return {"status": "error", "message": err}
    from google import genai

    client = genai.Client(api_key=config["GOOGLE_API_KEY"])
    next(iter(client.models.list()), None)
    return {"status": "success", "message": "Gemini API key is valid"}


def test_gcp(config: dict) -> dict:
    err = _missing(config, "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_CLOUD_PROJECT")
    if err:
        return {"status": "error", "message": err}
    creds_path = config["GOOGLE_APPLICATION_CREDENTIALS"]
    project = config["GOOGLE_CLOUD_PROJECT"]
    if not os.path.exists(creds_path):
        return {"status": "error", "message": f"Credentials file not found: {creds_path}"}

    from google.cloud import resourcemanager_v3
    from google.oauth2 import service_account

    creds = service_account.Credentials.from_service_account_file(creds_path)
    client = resourcemanager_v3.ProjectsClient(credentials=creds)
    proj = client.get_project(name=f"projects/{project}")
    return {
        "status": "success",
        "message": f"Connected to GCP project {proj.project_id} ({proj.display_name or '—'})",
    }


def test_aws(config: dict) -> dict:
    err = _missing(config, "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY")
    if err:
        return {"status": "error", "message": err}
    try:
        import boto3
    except ImportError:
        return {
            "status": "error",
            "message": "boto3 is not installed; run `pip install boto3` to enable AWS connection tests",
        }

    sts = boto3.client(
        "sts",
        aws_access_key_id=config["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=config["AWS_SECRET_ACCESS_KEY"],
        region_name=config.get("AWS_REGION") or "us-east-1",
    )
    ident = sts.get_caller_identity()
    return {
        "status": "success",
        "message": f"AWS account {ident['Account']} as {ident['Arn']}",
    }


def test_azure(config: dict) -> dict:
    err = _missing(config, "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET")
    if err:
        return {"status": "error", "message": err}
    import requests

    resp = requests.post(
        f"https://login.microsoftonline.com/{config['AZURE_TENANT_ID']}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": config["AZURE_CLIENT_ID"],
            "client_secret": config["AZURE_CLIENT_SECRET"],
            "scope": "https://management.azure.com/.default",
        },
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200 and "access_token" in (resp.json() or {}):
        return {"status": "success", "message": "Azure service principal authenticated"}
    desc = (resp.json() or {}).get("error_description", resp.text[:200])
    return {"status": "error", "message": f"Azure auth failed (HTTP {resp.status_code}): {desc}"}


def test_nvd(config: dict) -> dict:
    err = _missing(config, "NVD_API_KEY")
    if err:
        return {"status": "error", "message": err}
    import requests

    resp = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"resultsPerPage": 1},
        headers={"apiKey": config["NVD_API_KEY"]},
        timeout=15,
    )
    if resp.status_code == 200:
        total = resp.json().get("totalResults", "?")
        return {"status": "success", "message": f"NVD reachable; total CVEs indexed: {total}"}
    return {"status": "error", "message": f"NVD returned HTTP {resp.status_code}"}


def test_jira(config: dict) -> dict:
    err = _missing(config, "JIRA_URL", "JIRA_USER", "JIRA_TOKEN")
    if err:
        return {"status": "error", "message": err}
    import requests

    resp = requests.get(
        config["JIRA_URL"].rstrip("/") + "/rest/api/2/myself",
        auth=(config["JIRA_USER"], config["JIRA_TOKEN"]),
        headers={"Accept": "application/json"},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        me = resp.json() or {}
        who = me.get("displayName") or me.get("name") or config["JIRA_USER"]
        return {"status": "success", "message": f"Jira authenticated as {who}"}
    return {"status": "error", "message": f"Jira auth failed (HTTP {resp.status_code})"}


def test_github(config: dict) -> dict:
    err = _missing(config, "GITHUB_TOKEN")
    if err:
        return {"status": "error", "message": err}
    import requests

    resp = requests.get(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {config['GITHUB_TOKEN']}",
            "Accept": "application/vnd.github+json",
        },
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        return {
            "status": "success",
            "message": f"GitHub token valid for @{(resp.json() or {}).get('login')}",
        }
    return {"status": "error", "message": f"GitHub auth failed (HTTP {resp.status_code})"}


def test_anthropic(config: dict) -> dict:
    err = _missing(config, "ANTHROPIC_API_KEY")
    if err:
        return {"status": "error", "message": err}
    import requests

    resp = requests.get(
        "https://api.anthropic.com/v1/models",
        headers={
            "x-api-key": config["ANTHROPIC_API_KEY"],
            "anthropic-version": "2023-06-01",
        },
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        n = len((resp.json() or {}).get("data", []))
        return {"status": "success", "message": f"Anthropic API key valid; {n} models available"}
    return {"status": "error", "message": f"Anthropic auth failed (HTTP {resp.status_code})"}


def test_openai(config: dict) -> dict:
    err = _missing(config, "OPENAI_API_KEY")
    if err:
        return {"status": "error", "message": err}
    import requests

    resp = requests.get(
        "https://api.openai.com/v1/models",
        headers={"Authorization": f"Bearer {config['OPENAI_API_KEY']}"},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        n = len((resp.json() or {}).get("data", []))
        return {"status": "success", "message": f"OpenAI API key valid; {n} models available"}
    return {"status": "error", "message": f"OpenAI auth failed (HTTP {resp.status_code})"}


def test_confluence(config: dict) -> dict:
    err = _missing(config, "CONFLUENCE_URL", "CONFLUENCE_USER", "CONFLUENCE_TOKEN")
    if err:
        return {"status": "error", "message": err}
    import requests

    base = config["CONFLUENCE_URL"].rstrip("/")
    resp = requests.get(
        f"{base}/wiki/rest/api/user/current",
        auth=(config["CONFLUENCE_USER"], config["CONFLUENCE_TOKEN"]),
        headers={"Accept": "application/json"},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        me = resp.json() or {}
        who = me.get("displayName") or me.get("email") or config["CONFLUENCE_USER"]
        return {"status": "success", "message": f"Confluence authenticated as {who}"}
    return {"status": "error", "message": f"Confluence auth failed (HTTP {resp.status_code})"}


def test_notion(config: dict) -> dict:
    err = _missing(config, "NOTION_TOKEN")
    if err:
        return {"status": "error", "message": err}
    import requests

    resp = requests.get(
        "https://api.notion.com/v1/users/me",
        headers={
            "Authorization": f"Bearer {config['NOTION_TOKEN']}",
            "Notion-Version": "2022-06-28",
        },
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        body = resp.json() or {}
        bot_owner = ((body.get("bot") or {}).get("workspace_name")) or body.get("name") or "bot"
        return {"status": "success", "message": f"Notion token valid for workspace {bot_owner}"}
    return {"status": "error", "message": f"Notion auth failed (HTTP {resp.status_code})"}


def test_crowdstrike(config: dict) -> dict:
    err = _missing(config, "FALCON_CLIENT_ID", "FALCON_CLIENT_SECRET")
    if err:
        return {"status": "error", "message": err}
    import requests

    base = (config.get("FALCON_BASE_URL") or "https://api.crowdstrike.com").rstrip("/")
    resp = requests.post(
        f"{base}/oauth2/token",
        data={
            "client_id": config["FALCON_CLIENT_ID"],
            "client_secret": config["FALCON_CLIENT_SECRET"],
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code in (200, 201) and (resp.json() or {}).get("access_token"):
        return {"status": "success", "message": "CrowdStrike API credentials valid"}
    return {
        "status": "error",
        "message": f"CrowdStrike auth failed (HTTP {resp.status_code})",
    }


def test_qualys(config: dict) -> dict:
    err = _missing(config, "QUALYS_USERNAME", "QUALYS_PASSWORD", "QUALYS_BASE_URL")
    if err:
        return {"status": "error", "message": err}
    import requests

    base = config["QUALYS_BASE_URL"].rstrip("/")
    # /msp/about.php is a small XML endpoint that auths with basic and returns
    # platform info. Cheaper than listing assets.
    resp = requests.get(
        f"{base}/msp/about.php",
        auth=(config["QUALYS_USERNAME"], config["QUALYS_PASSWORD"]),
        headers={"X-Requested-With": "Security Mind"},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200 and "<ABOUT>" in resp.text:
        return {"status": "success", "message": "Qualys credentials valid"}
    return {
        "status": "error",
        "message": f"Qualys auth failed (HTTP {resp.status_code})",
    }


def test_local_docs(config: dict) -> dict:
    err = _missing(config, "LOCAL_DOCS_PATH")
    if err:
        return {"status": "error", "message": err}
    import os

    path = os.path.expanduser(config["LOCAL_DOCS_PATH"])
    if not os.path.exists(path):
        return {"status": "error", "message": f"Path does not exist: {path}"}
    if not os.path.isdir(path):
        return {"status": "error", "message": f"Path is not a directory: {path}"}
    if not os.access(path, os.R_OK):
        return {"status": "error", "message": f"Path is not readable: {path}"}
    # Quick scan for supported file types
    supported = (".md", ".txt", ".pdf", ".docx")
    n = sum(1 for root, _, files in os.walk(path) for f in files if f.lower().endswith(supported))
    return {
        "status": "success",
        "message": f"Readable directory with {n} supported document(s) (.md/.txt/.pdf/.docx).",
    }


def test_gitlab(config: dict) -> dict:
    err = _missing(config, "GITLAB_TOKEN")
    if err:
        return {"status": "error", "message": err}
    import requests

    base = (config.get("GITLAB_URL") or "https://gitlab.com").rstrip("/")
    resp = requests.get(
        f"{base}/api/v4/user",
        headers={"PRIVATE-TOKEN": config["GITLAB_TOKEN"]},
        timeout=_HTTP_TIMEOUT,
    )
    if resp.status_code == 200:
        me = resp.json() or {}
        who = me.get("username") or me.get("name") or "user"
        return {"status": "success", "message": f"GitLab token valid for @{who}"}
    return {"status": "error", "message": f"GitLab auth failed (HTTP {resp.status_code})"}


TESTERS: dict[str, Tester] = {
    "gemini": test_gemini,
    "anthropic": test_anthropic,
    "openai": test_openai,
    "gcp": test_gcp,
    "aws": test_aws,
    "azure": test_azure,
    "nvd": test_nvd,
    "jira": test_jira,
    "github": test_github,
    "gitlab": test_gitlab,
    "confluence": test_confluence,
    "notion": test_notion,
    "local_docs": test_local_docs,
    "crowdstrike": test_crowdstrike,
    "qualys": test_qualys,
}


def test_connection(provider: str, config: dict) -> dict:
    tester = TESTERS.get(provider.lower())
    if tester is None:
        return {
            "status": "error",
            "message": f"No connection test registered for provider '{provider}'",
        }
    try:
        return tester(config)
    except Exception as exc:
        logger.exception("test_connection for %s raised", provider)
        return {"status": "error", "message": str(exc)}
