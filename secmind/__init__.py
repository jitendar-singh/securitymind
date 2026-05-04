from .logging_config import setup_logging

setup_logging()

# Integration env-shim is no longer applied at import time — integrations are
# scoped per user, so the /chat handler applies the active user's vars per
# request via secmind.env_shim.apply_integrations_for_request.

from . import agent  # noqa: E402
