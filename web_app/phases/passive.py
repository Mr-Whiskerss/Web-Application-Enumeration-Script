"""
Passive Reconnaissance Phases

Non-intrusive information gathering using public data:
- Passive DNS, WHOIS & ASN lookups
- Certificate Transparency scanning
- Wayback Machine URL mining
- Google dorking (via Custom Search API or manual URLs)
- Email harvesting via theHarvester
- Subdomain enumeration & takeover detection
- Favicon hash computation (Shodan pivoting)
"""

import os
import re
import json
import time
import shutil
import socket
import hashlib
import base64
import subprocess
import logging
from datetime import datetime
from typing import Optional, List, Dict, Set
from urllib.parse import urlparse, parse_qs

# Third-party imports
import requests

try:
    import mmh3
    _HAS_MMH3 = True
except ImportError:
    _HAS_MMH3 = False

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    Fore = None

# Relative imports from web_app modules
from ..core.config import ScanConfig, TargetType, Finding, Severity, ScanState, ScopeChecker
from ..utils.logging import _log, section, run_cmd, _tool_ok
from ..utils.findings import add_finding
from ..core.session import make_session


logger = logging.getLogger("webrecon")

# Global takeover fingerprints dictionary
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

# Global discovery state (imported from main module)
try:
    from ..core.discovery import DISCOVERED
except ImportError:
    DISCOVERED = None


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
            if Fore:
                print(f"{Fore.GREEN}  ✓ crt.sh: {len(domains)} subdomains")
            else:
                print(f"  ✓ crt.sh: {len(domains)} subdomains")
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
            if Fore:
                print(f"{Fore.GREEN}  ✓ Wayback: {len(urls)} URLs")
            else:
                print(f"  ✓ Wayback: {len(urls)} URLs")

            # Feed URLs + params into shared state
            if DISCOVERED:
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
                if DISCOVERED:
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
        if Fore:
            print(f"{Fore.CYAN}  ℹ Dork URLs generated. Add --google-api-key to automate.")
        else:
            print(f"  ℹ Dork URLs generated. Add --google-api-key to automate.")
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
            if Fore:
                print(f"  {Fore.YELLOW}[SKIP] Subdomain enum — target is IP")
            else:
                print(f"  [SKIP] Subdomain enum — target is IP")
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
            if Fore:
                print(f"  {Fore.YELLOW}  [SCOPE] Filtered {before - len(subdomains)} out-of-scope subdomains")
            else:
                print(f"    [SCOPE] Filtered {before - len(subdomains)} out-of-scope subdomains")

    if subdomains:
        if _tool_ok("subjack", out):
            subs_file = f"/tmp/subs_{hashlib.md5(host.encode()).hexdigest()}.txt"
            open(subs_file, 'w').write('\n'.join(subdomains))
            run_cmd(["subjack", "-w", subs_file, "-t", "50", "-timeout", "30", "-ssl"],
                    "subjack takeover scan", out, cfg, 300)
        _takeover_fingerprints(subdomains, out, phase, cfg)

    st.mark(phase)


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
