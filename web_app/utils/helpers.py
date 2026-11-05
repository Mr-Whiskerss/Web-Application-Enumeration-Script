"""
WebRecon General Helper Utilities

String manipulation, URL/domain parsing, data formatting, validation utilities,
and other general helper functions that don't fit into specific categories.
"""

import os
import re
import json
from typing import Optional, List, Dict
from urllib.parse import urlparse
from dataclasses import asdict

try:
    from colorama import Fore
except ImportError:
    class Fore:
        CYAN = ""


# ═════════════════════════════════════════════════════════════════════════════
# INPUT HELPERS (loosened sanitise: allow host:port)
# ═════════════════════════════════════════════════════════════════════════════

def normalise(raw: str) -> str:
    """Normalize input string — extract netloc from URLs, strip trailing slashes."""
    raw = raw.strip()
    if re.match(r'^https?://', raw, re.I):
        return urlparse(raw).netloc
    return raw.rstrip('/')

def validate(target: str) -> Optional[str]:
    """Validate target is valid IPv4, IPv6, domain, or domain:port format.
    Returns TargetType.IP or TargetType.DOMAIN if valid, None otherwise."""
    # IPv4 check
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
        try:
            import ipaddress
            ipaddress.IPv4Address(target)
            return "ip"
        except ValueError:
            return None
    # Domain check (with or without port)
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', target):
        return "domain"
    # Allow host:port
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}:\d{1,5}$', target):
        return "domain"
    return None

def sanitise(value: str) -> str:
    """Sanitize input to block shell metacharacters while allowing host:port syntax.
    Raises ValueError if unsafe characters detected."""
    # Loosened: colon allowed (for host:port). Still blocks shell metachars.
    if re.search(r'[;&|`$<>()\\\'"{}]', value):
        raise ValueError(f"Unsafe characters in input: {value!r}")
    return value

def yes_no(prompt: str) -> bool:
    """Interactive yes/no prompt. Returns True for yes, False for no."""
    while True:
        ans = input(f"{Fore.CYAN}  {prompt} (y/n): ").strip().lower()
        if ans in ('y', 'yes'): return True
        if ans in ('n', 'no'):  return False

# ═════════════════════════════════════════════════════════════════════════════
# DIFF MODE
# ═════════════════════════════════════════════════════════════════════════════

def diff_findings(current: List, prev_file: str) -> Dict:
    """Compare current findings against previous JSON file.
    Returns dict with 'new', 'resolved', and 'unchanged' keys."""
    if not os.path.exists(prev_file):
        return {}
    try:
        prev = {f['title'] for f in json.load(open(prev_file))}
        curr = {f.title for f in current}
        return {
            "new":       [asdict(f) for f in current if f.title not in prev],
            "resolved":  list(prev - curr),
            "unchanged": len(curr & prev),
        }
    except Exception:
        return {}
