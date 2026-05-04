"""Pluggable threat modeling framework strategies."""
from .base import Framework, FrameworkResult
from .registry import detect_frameworks, get_by_name, ALL_FRAMEWORKS

__all__ = [
    "Framework",
    "FrameworkResult",
    "detect_frameworks",
    "get_by_name",
    "ALL_FRAMEWORKS",
]
