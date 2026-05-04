"""
Centralised logging configuration for secmind.

Call setup_logging() once at application startup (done automatically in
secmind/__init__.py).  Every other module should only do:

    import logging
    logger = logging.getLogger(__name__)
"""

import logging
import os

_configured = False


def setup_logging() -> None:
    """Configure the root 'secmind' logger exactly once."""
    global _configured
    if _configured:
        return

    level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    )

    root = logging.getLogger("secmind")
    root.setLevel(level)
    if not root.handlers:
        root.addHandler(handler)

    _configured = True
