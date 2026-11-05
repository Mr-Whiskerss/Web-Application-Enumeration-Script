"""
Finding Management

Handles:
- Finding data structure
- Finding storage and deduplication
- Finding output (Markdown, JSON)
- Webhook notifications
- PentestDB integration
"""

import json
import logging
import hashlib
import requests
import threading
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Set, Optional
from datetime import datetime

logger = logging.getLogger("webrecon")

try:
    from colorama import Fore
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = ""


class Severity(str, Enum):
    """Finding severity levels."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Finding:
    """A security finding from the scan."""
    title: str
    severity: Severity
    description: str
    evidence: str = ""
    recommendation: str = ""
    phase: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# Global findings storage
_findings: List[Finding] = []
_findings_lock = threading.Lock()
_finding_keys: Set[str] = set()  # dedup on (title | severity | evidence-hash)
_SEV_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def add_finding(f: Finding, output_file: str, cfg: Optional = None):
    """Add a finding to the global store, suppressing duplicates."""
    # Dedup on (title | severity | evidence-hash)
    key = (
        f"{f.title}|{f.severity.value}|"
        f"{hashlib.md5((f.evidence or '').encode()).hexdigest()}"
    )
    with _findings_lock:
        if key in _finding_keys:
            return
        _finding_keys.add(key)
        _findings.append(f)

    color = {
        Severity.INFO: Fore.CYAN,
        Severity.LOW: Fore.GREEN,
        Severity.MEDIUM: Fore.YELLOW,
        Severity.HIGH: Fore.RED,
        Severity.CRITICAL: Fore.MAGENTA,
    }.get(f.severity, Fore.WHITE)

    try:
        print(f"  {color}[{f.severity.value}] {f.title}")
    except:
        print(f"  [{f.severity.value}] {f.title}")

    _log_finding_to_report(f, output_file)

    # Push to webhook / pentestdb if configured
    if cfg:
        try:
            if cfg.webhook_url and _SEV_ORDER[f.severity] >= _SEV_ORDER[cfg.webhook_threshold]:
                webhook_notify(f, cfg)
        except Exception as e:
            if cfg.verbose:
                try:
                    print(f"  {Fore.YELLOW}⚠ webhook: {e}")
                except:
                    print(f"  ⚠ webhook: {e}")

        try:
            if cfg.pentestdb_url:
                pentestdb_push(f, cfg)
        except Exception as e:
            if cfg.verbose:
                try:
                    print(f"  {Fore.YELLOW}⚠ pentestdb: {e}")
                except:
                    print(f"  ⚠ pentestdb: {e}")


def _log_finding_to_report(f: Finding, output_file: str):
    """Log finding to Markdown report file."""
    icons = {
        Severity.INFO: "ℹ️",
        Severity.LOW: "🟢",
        Severity.MEDIUM: "🟡",
        Severity.HIGH: "🔴",
        Severity.CRITICAL: "🚨",
    }
    icon = icons.get(f.severity, "")
    lines = [
        f"\n### {icon} [{f.severity.value}] {f.title}",
        f"**Phase:** {f.phase}  |  **Time:** {f.timestamp}\n",
        f"**Description:** {f.description}\n",
    ]
    if f.evidence:
        lines.append(f"**Evidence:**\n```\n{f.evidence[:1500]}\n```\n")
    if f.recommendation:
        lines.append(f"**Recommendation:** {f.recommendation}\n")
    lines.append("---")
    _log_to_file(output_file, "\n".join(lines))


def _log_to_file(output_file: str, msg: str):
    """Append message to output file (thread-safe)."""
    log_lock = threading.Lock()
    with log_lock:
        with open(output_file, "a") as fh:
            fh.write(msg + "\n")


def webhook_notify(f: Finding, cfg):
    """POST a finding to a Discord/Slack incoming webhook URL."""
    color_map = {
        Severity.INFO: 0x3498DB,
        Severity.LOW: 0x2ECC71,
        Severity.MEDIUM: 0xF1C40F,
        Severity.HIGH: 0xE67E22,
        Severity.CRITICAL: 0xE74C3C,
    }
    url = cfg.webhook_url
    if not url:
        return

    try:
        # Discord-style embed
        if "discord" in url.lower():
            payload = {
                "embeds": [
                    {
                        "title": f"[{f.severity.value}] {f.title}",
                        "description": f.description[:1500],
                        "color": color_map.get(f.severity, 0x95A5A6),
                        "fields": [
                            {"name": "Target", "value": cfg.target, "inline": True},
                            {"name": "Phase", "value": f.phase or "n/a", "inline": True},
                        ],
                        "timestamp": f.timestamp,
                    }
                ]
            }
        else:
            # Slack-style
            payload = {
                "text": (
                    f"*[{f.severity.value}]* {f.title}\n"
                    f"_Target:_ `{cfg.target}` | _Phase:_ `{f.phase}`\n"
                    f"{f.description[:1500]}"
                )
            }

        proxies = {"http": cfg.proxy, "https": cfg.proxy} if cfg.proxy else None
        resp = requests.post(url, json=payload, timeout=5, verify=False, proxies=proxies)

        if resp.status_code >= 400:
            if logger:
                logger.warning(f"Webhook notification failed: HTTP {resp.status_code}")
        elif logger:
            logger.debug(f"Webhook notification sent for {f.severity.value}: {f.title}")

    except requests.exceptions.Timeout:
        if logger:
            logger.warning("Webhook notification timed out")
    except requests.exceptions.RequestException as e:
        if logger:
            logger.warning(f"Webhook notification failed: {type(e).__name__}: {e}")
    except Exception as e:
        if logger:
            logger.error(f"Unexpected error in webhook notification: {e}")


def pentestdb_push(f: Finding, cfg):
    """POST finding to a self-hosted pentestdb instance."""
    if not cfg.pentestdb_url:
        return

    try:
        endpoint = cfg.pentestdb_url.rstrip("/") + "/api/findings"
        payload = {
            "target": cfg.target,
            "title": f.title,
            "severity": f.severity.value,
            "description": f.description,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
            "phase": f.phase,
            "timestamp": f.timestamp,
            "tool": "WebRecon",
        }
        headers = {"Content-Type": "application/json"}
        if cfg.pentestdb_token:
            headers["Authorization"] = f"Bearer {cfg.pentestdb_token}"

        resp = requests.post(endpoint, json=payload, headers=headers, timeout=10, verify=False)

        if resp.status_code >= 400:
            if logger:
                logger.warning(f"PentestDB push failed: HTTP {resp.status_code}")
        elif logger:
            logger.debug(f"Finding pushed to PentestDB: {f.title}")

    except requests.exceptions.Timeout:
        if logger:
            logger.warning("PentestDB push timed out")
    except requests.exceptions.RequestException as e:
        if logger:
            logger.warning(f"PentestDB push failed: {type(e).__name__}: {e}")
    except Exception as e:
        if logger:
            logger.error(f"Unexpected error pushing to PentestDB: {e}")


def save_findings(findings: List[Finding], path: str):
    """Save findings to JSON file."""
    with open(path, "w") as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2, default=str)


def get_findings() -> List[Finding]:
    """Get all findings collected so far."""
    with _findings_lock:
        return _findings.copy()


def clear_findings():
    """Clear all findings (used when switching targets in batch mode)."""
    global _findings, _finding_keys
    with _findings_lock:
        _findings.clear()
        _finding_keys.clear()
