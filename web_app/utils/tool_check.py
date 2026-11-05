"""
Tool availability and permission checking utilities.

Provides functions to check if external tools/commands are available in PATH,
manage sudo requirements, and track missing tool dependencies for reporting.
"""

import os
import shutil
import threading
from typing import List, Set

# Module-level tracking of missing tools
_MISSING_TOOLS: Set[str] = set()
_MISSING_TOOLS_LOCK = threading.Lock()


def _tool_ok(name: str, output_file: str) -> bool:
    """Check if a tool is available in PATH. Logs and tracks if missing."""
    if shutil.which(name):
        return True
    with _MISSING_TOOLS_LOCK:
        _MISSING_TOOLS.add(name)
    msg = f"{name} not installed — skipping"
    try:
        from colorama import Fore
        print(f"  {Fore.YELLOW}⚠ {msg}")
        # Import _log from parent module to avoid circular dependency
        from web_app import _log
        _log(output_file, f"> ⚠️ {msg}")
    except Exception as e:
        import logging
        logger = logging.getLogger("webrecon")
        if logger:
            logger.warning(f"Failed to log tool check: {e}")
    return False


def _is_root() -> bool:
    """Check if running with root privileges."""
    return os.geteuid() == 0


def _sudo() -> List[str]:
    """Determine if sudo is needed/available.

    Returns:
        Empty list if running as root, otherwise ["sudo"].
    """
    return [] if _is_root() else ["sudo"]
