"""
Subprocess Execution Utilities

Provides safe command execution with timeout handling, error management,
and integrated logging for subprocess operations used across WebRecon.
"""

import subprocess
import logging
from typing import List, Tuple

from colorama import Fore

# Module-level logger reference (will be set by main application)
logger = None


# ═════════════════════════════════════════════════════════════════════════════
# EXCEPTIONS
# ═════════════════════════════════════════════════════════════════════════════

class ToolNotFound(Exception):
    """Tool is not installed or not in PATH."""
    pass


def run_cmd(cmd: List[str], desc: str, output_file: str, config,
            timeout: int = 300) -> Tuple[str, str, int]:
    """Execute a command safely with proper error handling and logging.

    Args:
        cmd: List of command arguments (for subprocess.run with shell=False)
        desc: Human-readable description of the command for logging
        output_file: Path to output log file for appending results
        config: ScanConfig object containing verbose flag and other settings
        timeout: Timeout in seconds (default 300)

    Returns:
        Tuple of (stdout, stderr, returncode)
    """
    print(f"{Fore.YELLOW}  → {desc}")
    _log(output_file, f"\n## {desc}\n**`{' '.join(cmd)}`**")

    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)

        if r.stdout:
            _log(output_file, f"```\n{r.stdout.strip()}\n```")

        if r.stderr:
            if config.verbose:
                _log(output_file, f"**stderr:**\n```\n{r.stderr.strip()}\n```")
            if r.returncode != 0 and logger:
                logger.debug(f"{desc} stderr: {r.stderr[:200]}")

        icon = Fore.GREEN + "✓" if r.returncode == 0 else Fore.RED + "✗"
        print(f"  {icon} {desc}")

        if r.returncode != 0 and logger:
            logger.warning(f"{desc} returned non-zero exit code: {r.returncode}")

        return r.stdout, r.stderr, r.returncode

    except subprocess.TimeoutExpired as e:
        msg = f"TIMEOUT after {timeout}s"
        print(f"  {Fore.RED}⏱ {desc}: {msg}")
        _log(output_file, f"> ⚠️ {msg}")
        if logger:
            logger.error(f"{desc} timed out: {e}")
        return "", "", -1

    except FileNotFoundError as e:
        msg = f"Not found: {cmd[0]}"
        print(f"  {Fore.RED}✗ {msg}")
        _log(output_file, f"> ⚠️ {msg}")
        if logger:
            logger.error(f"Tool not found: {cmd[0]} - {e}")
        raise ToolNotFound(f"Tool '{cmd[0]}' not found in PATH") from e

    except PermissionError as e:
        msg = f"Permission denied: {cmd[0]}"
        print(f"  {Fore.RED}✗ {msg}")
        _log(output_file, f"> ⚠️ {msg}")
        if logger:
            logger.error(f"Permission error running {cmd[0]}: {e}")
        return "", "", -1

    except Exception as e:
        msg = f"Error executing {desc}: {type(e).__name__}: {str(e)[:100]}"
        print(f"  {Fore.RED}✗ {msg}")
        _log(output_file, f"> ⚠️ {msg}")
        if logger:
            logger.exception(f"Failed to execute {desc}")
        return "", "", -1


# ═════════════════════════════════════════════════════════════════════════════
# OUTPUT LOGGING HELPERS (used by run_cmd)
# ═════════════════════════════════════════════════════════════════════════════

import threading

_log_lock = threading.Lock()


def _log(output_file: str, msg: str):
    """Thread-safe append to output file."""
    with _log_lock:
        with open(output_file, 'a') as fh:
            fh.write(msg + '\n')
