"""Framework registry: instantiation, name lookup, auto-detect."""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List

from .atlas import AtlasFramework
from .attack import AttackFramework
from .base import Framework
from .linddun import LinddunFramework
from .owasp_llm import OwaspLlmFramework
from .stride import StrideFramework

logger = logging.getLogger(__name__)


def _build_all() -> List[Framework]:
    return [
        StrideFramework(),
        AtlasFramework(),
        OwaspLlmFramework(),
        LinddunFramework(),
        AttackFramework(),
    ]


ALL_FRAMEWORKS: List[Framework] = _build_all()
_BY_NAME = {fw.name.lower(): fw for fw in ALL_FRAMEWORKS}
# Aliases for user input variations
_ALIASES = {
    "owasp": "owasp-llm",
    "owasp_llm": "owasp-llm",
    "owasp-llm-top-10": "owasp-llm",
    "llm": "owasp-llm",
    "attack": "att&ck",
    "mitre-attack": "att&ck",
    "mitre_attack": "att&ck",
    "att&ck": "att&ck",
    "atlas": "atlas",
    "mitre-atlas": "atlas",
    "stride": "stride",
    "linddun": "linddun",
}


def detect_frameworks(app_details: Dict[str, Any]) -> List[Framework]:
    """Return frameworks whose `applies_to` matches the given app_details. STRIDE always included as baseline."""
    selected: List[Framework] = []
    for fw in ALL_FRAMEWORKS:
        if fw.applies_to(app_details):
            selected.append(fw)
    # Guarantee STRIDE baseline
    if not any(fw.name == "STRIDE" for fw in selected):
        selected.insert(0, _BY_NAME["stride"])
    logger.info("Auto-detected frameworks: %s", [fw.name for fw in selected])
    return selected


def get_by_name(names: Iterable[str]) -> List[Framework]:
    """Resolve user-supplied names to Framework instances. Always includes STRIDE."""
    selected: List[Framework] = []
    seen = set()
    for raw in names:
        key = _ALIASES.get(raw.strip().lower(), raw.strip().lower())
        fw = _BY_NAME.get(key)
        if fw is None:
            logger.warning("Unknown framework name: %s", raw)
            continue
        if fw.name not in seen:
            selected.append(fw)
            seen.add(fw.name)
    if "STRIDE" not in seen:
        selected.insert(0, _BY_NAME["stride"])
    return selected
