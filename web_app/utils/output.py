"""
Output and logging utilities for WebRecon scanner.

Provides centralized output/logging functionality including:
  - _log() — Main file-based logging function with thread safety
  - section() — Section header formatting with color and markdown output
  - _log_finding_to_report() — Finding formatter with severity icons
  - save_findings() — Persist findings to JSON
  - run_cmd() — Subprocess runner with logging and error handling

All logging functions are thread-safe using module-level locks.
"""

import json
import threading
import subprocess
import logging
from typing import List, Tuple
from dataclasses import asdict

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    class Fore:
        RED=GREEN=YELLOW=BLUE=CYAN=MAGENTA=WHITE=""
    class Style:
        RESET_ALL=BRIGHT=""

# ═════════════════════════════════════════════════════════════════════════════
# LOGGING LOCKS
# ═════════════════════════════════════════════════════════════════════════════

_log_lock = threading.Lock()

# ═════════════════════════════════════════════════════════════════════════════
# MAIN LOGGING FUNCTION
# ═════════════════════════════════════════════════════════════════════════════

def _log(output_file: str, msg: str):
    """Write a message to the output file with thread-safe locking."""
    with _log_lock:
        with open(output_file, 'a') as fh:
            fh.write(msg + '\n')

# ═════════════════════════════════════════════════════════════════════════════
# SECTION FORMATTING
# ═════════════════════════════════════════════════════════════════════════════

def section(title: str, output_file: str):
    """Print a formatted section header to console and log file."""
    print(f"\n{Fore.BLUE}{'─'*55}")
    print(f"{Fore.BLUE}  {title}")
    print(f"{Fore.BLUE}{'─'*55}")
    _log(output_file, f"\n\n---\n# {title}\n")

# ═════════════════════════════════════════════════════════════════════════════
# FINDING REPORT FORMATTING
# ═════════════════════════════════════════════════════════════════════════════

def _log_finding_to_report(f, output_file: str):
    """Format and log a finding to the output report file.

    Args:
        f: Finding object with title, severity, description, evidence,
           recommendation, phase, and timestamp attributes.
        output_file: Path to the output report file.
    """
    icons = {
        "INFO": "ℹ️",
        "LOW": "🟢",
        "MEDIUM": "🟡",
        "HIGH": "🔴",
        "CRITICAL": "🚨"
    }

    # Handle both Severity enum and string values
    severity_str = f.severity.value if hasattr(f.severity, 'value') else f.severity
    icon = icons.get(severity_str, "")

    lines = [
        f"\n### {icon} [{severity_str}] {f.title}",
        f"**Phase:** {f.phase}  |  **Time:** {f.timestamp}\n",
        f"**Description:** {f.description}\n",
    ]
    if f.evidence:
        lines.append(f"**Evidence:**\n```\n{f.evidence[:1500]}\n```\n")
    if f.recommendation:
        lines.append(f"**Recommendation:** {f.recommendation}\n")
    lines.append("---")
    _log(output_file, '\n'.join(lines))

# ═════════════════════════════════════════════════════════════════════════════
# FINDINGS PERSISTENCE
# ═════════════════════════════════════════════════════════════════════════════

def save_findings(findings: List, path: str):
    """Persist findings to a JSON file.

    Args:
        findings: List of Finding objects.
        path: Output JSON file path.
    """
    with open(path, 'w') as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2, default=str)

# ═════════════════════════════════════════════════════════════════════════════
# SUBPROCESS EXECUTION WITH LOGGING
# ═════════════════════════════════════════════════════════════════════════════

def run_cmd(cmd: List[str], desc: str, output_file: str, config,
            timeout: int = 300) -> Tuple[str, str, int]:
    """Execute a command safely with proper error handling and logging.

    Args:
        cmd: Command as list of arguments (shell=False).
        desc: Human-readable description of the command.
        output_file: Path to the output report file.
        config: ScanConfig object with verbose flag and error logger.
        timeout: Command timeout in seconds (default: 300).

    Returns:
        Tuple of (stdout, stderr, returncode).
        On timeout or error: ("", "", -1).

    Raises:
        ToolNotFound: If the command executable is not found in PATH.
    """
    # Import here to avoid circular dependencies
    from web_app import logger, ToolNotFound

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
