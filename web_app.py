#!/usr/bin/env python3
"""
WebRecon v2.0 — Comprehensive Web Application Enumeration Tool
Improvements over v1: parallelism, scope enforcement, structured findings,
resumable state, diff mode, proxy/UA support, and extensive new checks.
"""

import os
import re
import sys
import json
import time
import shutil
import socket
import hashlib
import subprocess
import ipaddress
import threading
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional, List, Dict, Tuple
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
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

if _MISSING:
    print(f"[!] Missing packages: pip install {' '.join(_MISSING)}")
    sys.exit(1)

# ── Constants ─────────────────────────────────────────────────────────────────
VERSION        = "2.0.0"
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
    target:       str
    target_type:  TargetType
    base_url:     str
    output_prefix: str
    proxy:        Optional[str]  = None
    user_agent:   str            = DEFAULT_UA
    timeout:      int            = DEFAULT_TIMEOUT
    oob_url:      Optional[str]  = None
    scope_file:   Optional[str]  = None
    auto:         bool           = False
    rate:         int            = 50
    delay:        float          = 0.0
    full_ports:   bool           = False
    google_api_key: Optional[str]= None
    google_cx:    Optional[str]  = None
    diff_file:    Optional[str]  = None
    threads:      int            = 5
    verbose:      bool           = False

# ── Thread-safe findings store ────────────────────────────────────────────────
_findings: List[Finding] = []
_findings_lock = threading.Lock()

def add_finding(f: Finding, output_file: str):
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
# SCOPE ENFORCEMENT
# ═════════════════════════════════════════════════════════════════════════════

class ScopeChecker:
    def __init__(self, scope_file: Optional[str] = None):
        self.domains: List[str] = []
        self.cidrs:   List[ipaddress.IPv4Network] = []
        self.enabled  = scope_file is not None
        if scope_file and os.path.exists(scope_file):
            for line in open(scope_file):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                try:
                    self.cidrs.append(ipaddress.IPv4Network(line, strict=False))
                except ValueError:
                    self.domains.append(line.lower().lstrip('*.'))

    def check(self, target: str) -> bool:
        if not self.enabled:
            return True
        try:
            addr = ipaddress.IPv4Address(target)
            return any(addr in net for net in self.cidrs)
        except ValueError:
            pass
        t = target.lower()
        return any(t == d or t.endswith('.' + d) for d in self.domains)

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
# HTTP SESSION
# ═════════════════════════════════════════════════════════════════════════════

def make_session(config: ScanConfig) -> "requests.Session":
    s = requests.Session()
    s.headers["User-Agent"] = config.user_agent
    s.verify = False
    if config.proxy:
        s.proxies = {"http": config.proxy, "https": config.proxy}
    return s

def detect_scheme(target: str, config: ScanConfig) -> str:
    for scheme in ("https", "http"):
        try:
            requests.get(f"{scheme}://{target}", timeout=config.timeout,
                         verify=False, headers={"User-Agent": config.user_agent},
                         proxies={"http": config.proxy, "https": config.proxy} if config.proxy else None,
                         allow_redirects=False)
            print(f"{Fore.GREEN}  ✓ Scheme detected: {scheme}")
            return scheme
        except Exception:
            continue
    return "http"

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
# INPUT HELPERS
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
    return None

def sanitise(value: str) -> str:
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

    run_cmd(["nslookup", target], "NSLookup", out, cfg)

    if tt == TargetType.DOMAIN and _tool_ok("dnsrecon", out):
        run_cmd(["dnsrecon", "-d", target, "-t", "std"], "DNSRecon", out, cfg, 120)

    # WHOIS — flag recently registered domains
    if shutil.which("whois"):
        stdout, _, _ = run_cmd(["whois", target], "WHOIS", out, cfg, 30)
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
                            phase=phase), out)

    # ASN via ipinfo.io
    try:
        lookup_ip = target
        if tt == TargetType.DOMAIN:
            try: lookup_ip = socket.gethostbyname(target)
            except Exception: pass
        sess = make_session(cfg)
        r = sess.get(f"https://ipinfo.io/{lookup_ip}/json", timeout=cfg.timeout)
        if r.ok:
            data = r.json()
            _log(out, f"```json\n{json.dumps(data, indent=2)}\n```")
            add_finding(Finding(
                title="ASN & Network Information",
                severity=Severity.INFO,
                description=f"{lookup_ip} → {data.get('org','unknown')} | {data.get('city','')}, {data.get('country','')}",
                evidence=json.dumps(data, indent=2),
                phase=phase), out)
    except Exception as e:
        _log(out, f"> ASN lookup failed: {e}")

    # IPv6
    if tt == TargetType.DOMAIN:
        try:
            addrs = list({r[4][0] for r in socket.getaddrinfo(target, None, socket.AF_INET6)})
            if addrs:
                add_finding(Finding(
                    title="IPv6 Address(es) Detected",
                    severity=Severity.INFO,
                    description=f"Target exposes IPv6: {addrs}. Verify WAF/access controls cover IPv6.",
                    evidence=str(addrs),
                    recommendation="Ensure security controls (WAF, monitoring) apply equally to IPv6.",
                    phase=phase), out)
        except Exception:
            pass

    st.mark(phase)


def phase_cert_transparency(target: str, tt: TargetType, cfg: ScanConfig,
                             out: str, st: ScanState):
    phase = "cert_transparency"
    if st.done(phase) or tt != TargetType.DOMAIN: return
    section("Certificate Transparency (crt.sh)", out)
    try:
        sess = make_session(cfg)
        r = sess.get(f"https://crt.sh/?q=%.{target}&output=json", timeout=30)
        if r.ok:
            domains = sorted({
                d.strip().lstrip('*.')
                for cert in r.json()
                for d in cert.get('name_value', '').split('\n')
                if target in d
            })
            _log(out, f"Found {len(domains)} unique entries:\n```\n" + '\n'.join(domains[:200]) + "\n```")
            print(f"{Fore.GREEN}  ✓ crt.sh: {len(domains)} subdomains")
            add_finding(Finding(
                title=f"Certificate Transparency: {len(domains)} Subdomains",
                severity=Severity.INFO,
                description=f"crt.sh reveals {len(domains)} subdomains for {target}.",
                evidence='\n'.join(domains[:50]),
                recommendation="Review for forgotten or unpatched assets.",
                phase=phase), out)
    except Exception as e:
        _log(out, f"> crt.sh failed: {e}")
    st.mark(phase)


def phase_wayback(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "wayback"
    if st.done(phase): return
    section("Wayback Machine URL Mining", out)
    try:
        sess = make_session(cfg)
        url = (f"http://web.archive.org/cdx/search/cdx?url={target}/*"
               "&output=json&fl=original&collapse=urlkey&limit=500")
        r = sess.get(url, timeout=30)
        if r.ok:
            rows = r.json()
            urls = [row[0] for row in rows[1:]] if len(rows) > 1 else []
            _log(out, f"Found {len(urls)} archived URLs\n```\n" + '\n'.join(urls[:200]) + "\n```")
            print(f"{Fore.GREEN}  ✓ Wayback: {len(urls)} URLs")
            for kw in ('admin', 'api', 'backup', 'config', 'debug', 'upload', 'test', 'dev'):
                hits = [u for u in urls if kw in u.lower()]
                if hits:
                    add_finding(Finding(
                        title=f"Wayback: Historical '{kw}' Endpoints",
                        severity=Severity.LOW,
                        description=f"{len(hits)} archived URLs contain '{kw}'.",
                        evidence='\n'.join(hits[:10]),
                        recommendation="Verify whether these endpoints still exist and are secured.",
                        phase=phase), out)
    except Exception as e:
        _log(out, f"> Wayback failed: {e}")
    st.mark(phase)


def phase_google_dorks(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "google_dorks"
    if st.done(phase): return
    section("Google Dorking", out)
    dorks = [
        f"site:{target}",
        f"site:{target} filetype:pdf",
        f"site:{target} filetype:xls OR filetype:xlsx",
        f"site:{target} inurl:admin",
        f"site:{target} inurl:login",
        f"site:{target} inurl:config OR inurl:backup",
        f"site:{target} intext:\"error\" OR intext:\"exception\" OR intext:\"stack trace\"",
        f"site:{target} intext:\"username\" intext:\"password\"",
        f"site:{target} ext:env OR ext:git OR ext:svn",
        f"site:{target} \"index of\"",
        f"site:{target} inurl:api",
    ]
    _log(out, "## Google Dork URLs\n")
    for d in dorks:
        enc = d.replace(' ', '+')
        _log(out, f"- [{d}](https://www.google.com/search?q={enc})")

    if cfg.google_api_key and cfg.google_cx:
        sess = make_session(cfg)
        for dork in dorks[:5]:
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
        run_cmd(["theHarvester", "-d", target, "-b", "bing,google,duckduckgo", "-l", "200"],
                "theHarvester", out, cfg, 180)
    st.mark(phase)


def phase_subdomain_enum(target: str, tt: TargetType, cfg: ScanConfig,
                          out: str, st: ScanState):
    phase = "subdomain_enum"
    if st.done(phase) or tt != TargetType.DOMAIN:
        if tt != TargetType.DOMAIN:
            print(f"  {Fore.YELLOW}[SKIP] Subdomain enum — target is IP")
        return
    section("Subdomain Enumeration & Takeover Detection", out)

    subdomains = []
    if _tool_ok("subfinder", out):
        stdout, _, _ = run_cmd(["subfinder", "-d", target, "-silent"],
                               "subfinder", out, cfg, 120)
        if stdout:
            subdomains = [s.strip() for s in stdout.splitlines() if s.strip()]

    if subdomains:
        # subjack
        if _tool_ok("subjack", out):
            subs_file = f"/tmp/subs_{hashlib.md5(target.encode()).hexdigest()}.txt"
            open(subs_file, 'w').write('\n'.join(subdomains))
            run_cmd(["subjack", "-w", subs_file, "-t", "50", "-timeout", "30", "-ssl"],
                    "subjack takeover scan", out, cfg, 300)

        # Python fingerprint check
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
    _log(out, "\n## Takeover Fingerprint Check")
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
                        r = requests.get(f"https://{sub}", timeout=5, verify=False)
                        if fp.lower() in r.text.lower():
                            add_finding(Finding(
                                title=f"Subdomain Takeover: {sub}",
                                severity=Severity.HIGH,
                                description=f"{sub} → CNAME {cname} ({svc}) returns takeover fingerprint.",
                                evidence=f"CNAME: {cname}\nFingerprint: {fp}",
                                recommendation="Remove dangling DNS record or reclaim the resource.",
                                phase=phase), out)
                    except Exception:
                        pass
        except Exception:
            continue

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 2 — ACTIVE RECONNAISSANCE
# ═════════════════════════════════════════════════════════════════════════════

def phase_port_scan(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "port_scan"
    if st.done(phase): return
    section("Port Scanning (nmap)", out)
    if not _tool_ok("nmap", out):
        st.mark(phase); return

    sp = _sudo()
    if cfg.full_ports:
        run_cmd(sp + ["nmap", "-vv", "-sV", "-Pn", "-p-", "--min-rate", "1000",
                      "-oA", f"/tmp/nmap_full_{target}", target],
                "Nmap full TCP scan", out, cfg, 2400)
    else:
        ports = ("21,22,23,25,53,80,81,88,110,143,389,443,445,465,587,636,993,995,"
                 "1080,1443,2049,3000,3306,3389,4443,4848,5000,5432,5900,6379,7001,"
                 "7443,8000,8080,8081,8443,8444,8888,9000,9090,9200,9443,10000,27017")
        run_cmd(sp + ["nmap", "-vv", "-sV", "-Pn", f"-p{ports}",
                      "-oA", f"/tmp/nmap_web_{target}", target],
                "Nmap web & common ports", out, cfg, 600)

    run_cmd(sp + ["nmap", "--script=http-methods", "-p", "80,443,8080,8443", target],
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
                phase=phase), out)

    # Header-based CDN detection
    cdn_sigs = {
        "Cloudflare":   ["cf-ray", "cf-cache-status"],
        "AWS CloudFront":["x-amz-cf-id", "x-amz-cf-pop"],
        "Akamai":       ["x-akamai-transformed"],
        "Fastly":       ["x-fastly-request-id"],
        "Azure CDN":    ["x-msedge-ref"],
        "Sucuri":       ["x-sucuri-id"],
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
                phase=phase), out)
    except Exception as e:
        _log(out, f"> CDN check failed: {e}")
    st.mark(phase)


def phase_vhost_fuzz(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "vhost_fuzz"
    if st.done(phase): return
    section("Virtual Host Fuzzing", out)

    if not _tool_ok("ffuf", out):
        st.mark(phase); return

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
             "-H", f"Host: FUZZ.{target}",
             "-mc", "200,301,302,307,401,403",
             "-fs", fs, "-t", str(min(cfg.rate, 50)), "-timeout", "10"],
            "ffuf vhost fuzzing", out, cfg, 300)
    st.mark(phase)

# ═════════════════════════════════════════════════════════════════════════════
# PHASE 3 — TECHNOLOGY & CONTENT DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def phase_tech_detection(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "tech_detection"
    if st.done(phase): return
    section("Technology Detection", out)
    if _tool_ok("whatweb", out):
        run_cmd(["whatweb", "-v", "-a", "3", cfg.base_url], "WhatWeb", out, cfg, 60)
    if _tool_ok("webanalyze", out):
        run_cmd(["webanalyze", "-host", cfg.base_url], "webanalyze", out, cfg, 60)
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
                        phase=phase), out)
        except Exception as e:
            _log(out, f"> {path}: {e}")
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
        run_cmd(cmd, f"ffuf general discovery ({os.path.basename(wl)})", out, cfg, 600)

    # Admin panel focused wordlist
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

        # Security headers
        for hdr, (sev, rec) in _SEC_HEADERS.items():
            if hdr not in hdrs:
                add_finding(Finding(
                    title=f"Missing Header: {hdr}",
                    severity=sev,
                    description=f"Response does not include `{hdr}`.",
                    evidence=f"Checked: {cfg.base_url}",
                    recommendation=rec,
                    phase=phase), out)

        # Information disclosure headers
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
                    phase=phase), out)

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
                    phase=phase), out)

        # HTTP Basic Auth detection
        if r.status_code == 401 and 'www-authenticate' in hdrs:
            add_finding(Finding(
                title="HTTP Basic Authentication Detected",
                severity=Severity.MEDIUM,
                description=f"Realm: {hdrs['www-authenticate']}",
                evidence=f"HTTP 401 + WWW-Authenticate: {hdrs['www-authenticate']}",
                recommendation="Prefer OAuth/OIDC. Enforce strong credentials.",
                phase=phase), out)

        # HTTP/2 check
        try:
            res = subprocess.run(["curl", "--http2", "-sI", cfg.base_url, "--max-time", "5"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
            if "HTTP/2" in res.stdout:
                _log(out, "> HTTP/2 supported")
        except Exception:
            pass

        # Redirect chain
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
                        phase=phase), out)
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
    test_origins = [
        "https://evil.com",
        f"https://{target}.evil.com",
        f"https://evil.{target}",
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
                    phase=phase), out)
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
                        phase=phase), out)
                except Exception:
                    pass
        except Exception:
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
    if not cfg.auto and not yes_no("Run Nikto scan?"):
        _log(out, "> Nikto skipped."); st.mark(phase); return
    section("Nikto Web Vulnerability Scan", out)
    if _tool_ok("nikto", out):
        run_cmd(["nikto", "-h", cfg.base_url, "-Tuning", "123bde",
                 "-useragent", cfg.user_agent], "Nikto", out, cfg, 900)
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
                            phase=phase), out)
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
                    phase=phase), out)
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
                        phase=phase), out)
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
                    phase=phase), out)
        except Exception:
            continue
    st.mark(phase)


def phase_xxe(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "xxe"
    if st.done(phase): return
    section("XXE Probe", out)
    if not cfg.oob_url:
        _log(out, "> XXE skipped — no --oob-url provided.")
        print(f"  {Fore.YELLOW}⚠ XXE skipped — provide --oob-url (interactsh / Burp Collaborator)")
        st.mark(phase); return

    payload = (f'<?xml version="1.0"?>\n'
               f'<!DOCTYPE x [<!ENTITY xxe SYSTEM "http://{cfg.oob_url}/xxe">]>\n'
               f'<root><data>&xxe;</data></root>')
    sess = make_session(cfg)
    for path in ["/api/", "/upload", "/import", "/xml", "/soap", "/parse"]:
        try:
            sess.post(f"{cfg.base_url}{path}", data=payload,
                      headers={"Content-Type": "application/xml"}, timeout=cfg.timeout)
        except Exception:
            continue

    add_finding(Finding(
        title="XXE Probe Sent",
        severity=Severity.INFO,
        description=f"XXE payloads sent. Monitor {cfg.oob_url} for DNS/HTTP callbacks.",
        recommendation="Disable external entity processing in all XML parsers.",
        phase=phase), out)
    st.mark(phase)


def phase_default_creds(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "default_creds"
    if st.done(phase): return
    section("Default Credential Testing", out)

    # (indicator_path, login_path, user_field, pass_field, username, password, success_text)
    PLATFORMS = [
        ("/manager/html",  "/manager/html",           None,          None,    "tomcat",  "tomcat",  None),
        ("/manager/html",  "/manager/html",           None,          None,    "admin",   "admin",   None),
        ("/jenkins",       "/j_acegi_security_check", "j_username",  "j_password", "admin", "admin", "Dashboard"),
        ("/wp-login.php",  "/wp-login.php",           "log",         "pwd",   "admin",   "admin",   "wp-admin"),
        ("/grafana",       "/api/login",              None,          None,    "admin",   "admin",   None),
    ]
    sess = make_session(cfg)
    for indicator, login_path, uf, pf, user, pwd, success_text in PLATFORMS:
        try:
            check = sess.get(f"{cfg.base_url}{indicator}", timeout=cfg.timeout)
            if check.status_code not in (200, 401, 403): continue
        except Exception:
            continue
        login_url = f"{cfg.base_url}{login_path}"
        try:
            if uf is None:
                r = sess.get(login_url, auth=(user, pwd), timeout=cfg.timeout)
            else:
                r = sess.post(login_url, data={uf: user, pf: pwd},
                              timeout=cfg.timeout, allow_redirects=True)
            success = (r.status_code in (200, 302) and
                       (success_text is None or success_text.lower() in r.text.lower()) and
                       (uf is None and check.status_code == 401 and r.status_code == 200
                        or success_text and success_text.lower() in r.text.lower()))
            if success:
                add_finding(Finding(
                    title=f"Default Credentials Valid: {login_path}",
                    severity=Severity.CRITICAL,
                    description=f"Default credentials `{user}`/`{pwd}` accepted at {login_path}",
                    evidence=f"POST {login_url} → HTTP {r.status_code}",
                    recommendation="Change default credentials immediately. Enforce a strong password policy.",
                    phase=phase), out)
        except Exception:
            continue
    st.mark(phase)


def phase_cloud_buckets(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "cloud_buckets"
    if st.done(phase): return
    section("Cloud Storage Bucket Enumeration", out)

    parts = target.split('.')
    base_names = [parts[-2] if len(parts) >= 2 else target,
                  target.replace('.', '-'), target.replace('.', '')]
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
                            phase=phase), out)
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
# FINAL REPORT
# ═════════════════════════════════════════════════════════════════════════════

def write_summary(cfg: ScanConfig, out: str, findings: List[Finding], start: datetime):
    duration = datetime.now() - start
    counts = Counter(f.severity for f in findings)
    _log(out, "\n\n---\n# Summary\n")
    _log(out, f"| Field | Value |\n|---|---|\n"
              f"| Target | `{cfg.target}` |\n"
              f"| Base URL | {cfg.base_url} |\n"
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

# ═════════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING & MAIN
# ═════════════════════════════════════════════════════════════════════════════

def parse_args():
    p = ArgumentParser(
        description="WebRecon Pro v2.0 — Comprehensive Web Application Enumeration",
        formatter_class=RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python web_app_pro.py -t example.com
  python web_app_pro.py -t example.com --proxy http://127.0.0.1:8080 --oob-url xxx.interactsh.com
  python web_app_pro.py -t example.com --auto --full-ports --diff previous.findings.json
  python web_app_pro.py -t example.com --resume
        """)
    p.add_argument("-t", "--target",        help="Target domain or IP")
    p.add_argument("-o", "--output",        default="webrecon", help="Output file prefix")
    p.add_argument("--auto",   "-a",        action="store_true", help="Non-interactive (skip prompts)")
    p.add_argument("--proxy",               help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--user-agent",          default=DEFAULT_UA, help="Custom User-Agent")
    p.add_argument("--timeout",             type=int, default=10, help="HTTP timeout (s)")
    p.add_argument("--rate",                type=int, default=50, help="ffuf thread rate")
    p.add_argument("--delay",               type=float, default=0.0, help="ffuf inter-request delay (s)")
    p.add_argument("--oob-url",             help="OOB callback host for XXE/SSRF (e.g. interactsh hostname)")
    p.add_argument("--scope-file",          help="Scope file: CIDRs or domains, one per line")
    p.add_argument("--full-ports",          action="store_true", help="Full port scan (-p-)")
    p.add_argument("--google-api-key",      help="Google Custom Search API key")
    p.add_argument("--google-cx",           help="Google Custom Search Engine ID")
    p.add_argument("--diff",                dest="diff_file", help="Previous findings JSON for diff mode")
    p.add_argument("--resume",              action="store_true", help="Resume interrupted scan")
    p.add_argument("--fresh",               action="store_true", help="Clear state and start fresh")
    p.add_argument("--threads",             type=int, default=5, help="Parallel phase threads")
    p.add_argument("-v", "--verbose",       action="store_true", help="Show tool stderr")
    return p.parse_args()


def main():
    args = parse_args()

    print(f"\n{Fore.MAGENTA}{'═'*60}")
    print(f"{Fore.MAGENTA}  WebRecon Pro v{VERSION}")
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

    out      = args.output + ".md"
    findings = args.output + ".findings.json"
    state_f  = args.output + ".state.json"

    scope = ScopeChecker(args.scope_file)
    if not scope.check(target):
        print(f"{Fore.RED}  [!] {target} is OUT OF SCOPE — aborting."); sys.exit(1)

    state = ScanState(state_f)
    if args.fresh:
        state.clear()
        print(f"{Fore.YELLOW}  [FRESH] State cleared.")

    # Detect HTTP scheme
    print(f"\n{Fore.CYAN}  Detecting scheme for {target}…")
    _tmp_cfg = type('C', (), {'timeout': args.timeout, 'user_agent': args.__dict__.get('user_agent', DEFAULT_UA),
                              'proxy': args.proxy})()
    scheme = detect_scheme(target, _tmp_cfg)

    cfg = ScanConfig(
        target=target, target_type=tt,
        base_url=f"{scheme}://{target}",
        output_prefix=args.output,
        proxy=args.proxy,
        user_agent=args.__dict__.get('user_agent', DEFAULT_UA),
        timeout=args.timeout,
        oob_url=args.oob_url,
        scope_file=args.scope_file,
        auto=args.auto,
        rate=args.rate,
        delay=args.delay,
        full_ports=args.full_ports,
        google_api_key=args.google_api_key,
        google_cx=args.google_cx,
        diff_file=args.diff_file,
        threads=args.threads,
        verbose=args.verbose,
    )

    start = datetime.now()

    # Initialise report file
    if not (args.resume and os.path.exists(out)):
        with open(out, 'w') as fh:
            fh.write(f"# WebRecon Pro Report\n\n"
                     f"| | |\n|---|---|\n"
                     f"| **Target** | `{target}` ({tt.value}) |\n"
                     f"| **Base URL** | {cfg.base_url} |\n"
                     f"| **Started** | {start.isoformat()} |\n"
                     f"| **Tool** | WebRecon Pro v{VERSION} |\n\n---\n")
    else:
        _log(out, f"\n\n---\n*Resumed at {start.isoformat()}*\n")

    print(f"\n{Fore.CYAN}  Target:   {target} ({tt.value})")
    print(f"{Fore.CYAN}  Base URL: {cfg.base_url}")
    print(f"{Fore.CYAN}  Output:   {out}")
    if cfg.proxy:  print(f"{Fore.CYAN}  Proxy:    {cfg.proxy}")
    if cfg.oob_url:print(f"{Fore.CYAN}  OOB:      {cfg.oob_url}")
    if not _is_root():
        print(f"\n{Fore.YELLOW}  ⚠ Not root — nmap OS detection will use sudo.")

    try:
        # ── Phase 1: Passive (parallelised) ────────────────────────────────
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
        phase_subdomain_enum(target, tt, cfg, out, state)

        # ── Phase 2: Active ─────────────────────────────────────────────────
        print(f"\n{Fore.MAGENTA}[ PHASE 2 — ACTIVE RECONNAISSANCE ]")
        phase_port_scan(target, cfg, out, state)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futs = {
                pool.submit(phase_waf_cdn, target, cfg, out, state):   "waf",
                pool.submit(phase_vhost_fuzz, target, cfg, out, state):"vhost",
            }
            for fut in as_completed(futs):
                try: fut.result()
                except Exception as e: print(f"  {Fore.RED}✗ {futs[fut]}: {e}")

        # ── Phase 3: Technology & Content ───────────────────────────────────
        print(f"\n{Fore.MAGENTA}[ PHASE 3 — TECHNOLOGY & CONTENT DISCOVERY ]")
        phase_tech_detection(target, cfg, out, state)
        phase_robots_sitemap(target, tt, cfg, out, state)
        phase_content_discovery(target, cfg, out, state)

        # ── Phase 4: HTTP Analysis (parallelised) ───────────────────────────
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

        # ── Phase 5: Vulnerability Scanning ─────────────────────────────────
        print(f"\n{Fore.MAGENTA}[ PHASE 5 — VULNERABILITY SCANNING ]")
        phase_ssl_tls(target, cfg, out, state)
        phase_nikto(target, cfg, out, state)
        with ThreadPoolExecutor(max_workers=4) as pool:
            futs = {
                pool.submit(phase_js_analysis, target, cfg, out, state):     "js",
                pool.submit(phase_graphql, target, cfg, out, state):         "graphql",
                pool.submit(phase_path_traversal, target, cfg, out, state):  "lfi",
                pool.submit(phase_open_redirect, target, cfg, out, state):   "redirect",
            }
            for fut in as_completed(futs):
                try: fut.result()
                except Exception as e: print(f"  {Fore.RED}✗ {futs[fut]}: {e}")

        phase_xxe(target, cfg, out, state)
        phase_default_creds(target, cfg, out, state)

        # ── Phase 6: Infrastructure ──────────────────────────────────────────
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
