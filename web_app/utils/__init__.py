"""
WebRecon Utilities

Common helper functions used across the tool.
"""

from .helpers import (
    normalise,
    validate,
    sanitise,
    yes_no,
    _tool_ok,
    run_cmd,
    detect_catchall,
    looks_like_catchall,
)

__all__ = [
    "normalise",
    "validate",
    "sanitise",
    "yes_no",
    "_tool_ok",
    "run_cmd",
    "detect_catchall",
    "looks_like_catchall",
]
