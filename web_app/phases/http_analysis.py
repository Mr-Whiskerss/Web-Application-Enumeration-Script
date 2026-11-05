"""
HTTP Analysis Phases

Analysis of HTTP responses and security headers:
- Security header analysis (HSTS, CSP, etc.)
- CORS misconfiguration detection
- Host header injection testing
- CRLF injection probing
- CSRF token presence checking
- JWT analysis (algorithms, expiration, weak secrets)
- OAuth/OIDC endpoint enumeration
- Content Security Policy analysis
"""

import re
import json
import base64
import time
import subprocess
from typing import Set, Dict
from urllib.parse import urlparse, urljoin

from web_app.core.session import make_session, RateLimitedSession
from web_app.core.state import DISCOVERED, add_finding, _log
from web_app.core.config import ScanConfig, ScanState, Severity, Finding


# Security headers configuration
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

# CSRF token hints
_CSRF_TOKEN_HINTS = [
    "csrf", "xsrf", "authenticity_token", "__requestverificationtoken",
    "_token", "csrfmiddlewaretoken", "csrf_token", "csrftoken", "nonce",
    "anticsrf", "__csrf", "requestverificationtoken", "form_token", "_csrf",
]


def section(title: str, output_file: str):
    """Print section header (imported from main)."""
    from colorama import Fore
    print(f"\n{Fore.BLUE}{'─'*55}")
    print(f"{Fore.BLUE}  {title}")
    print(f"{Fore.BLUE}{'─'*55}")
    _log(output_file, f"\n\n---\n# {title}\n")


def looks_like_catchall(cfg: "ScanConfig", response_text: str,
                        response_bytes: int) -> bool:
    """Return True if a 200 response matches the catch-all baseline."""
    if not cfg.catchall_active:
        return False
    size_diff_pct = (abs(response_bytes - cfg.catchall_size) /
                     max(cfg.catchall_size, 1)) * 100
    if size_diff_pct < 10:
        return True
    if cfg.catchall_body and response_text:
        head_baseline = cfg.catchall_body[:2000]
        head_actual   = response_text[:2000]
        if head_baseline == head_actual:
            return True
    return False


def _form_has_csrf_token(form_html: str) -> bool:
    """True if any input/name/id inside the form looks like a CSRF token, or a
    high-entropy hidden value is present (some frameworks use random field names)."""
    fl = form_html.lower()
    if any(h in fl for h in _CSRF_TOKEN_HINTS):
        return True
    # Hidden input with a long, token-shaped value (>=24 chars, mixed) — heuristic
    for m in re.finditer(r'<input[^>]*type=["\']?hidden["\']?[^>]*>', form_html, re.I):
        val = re.search(r'value=["\']([^"\']{24,})["\']', m.group(0), re.I)
        if val and re.search(r'[0-9]', val.group(1)) and re.search(r'[a-zA-Z]', val.group(1)):
            return True
    return False


def phase_header_analysis(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Security header & cookie analysis: HSTS, CSP, X-Frame-Options, etc."""
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
    """CORS misconfiguration detection: tests for wildcard origins & credentials."""
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
    """OAuth / OIDC endpoint enumeration: probes for common config endpoints."""
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
    from web_app.core.state import _findings, _findings_lock
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

    import hashlib
    import logging
    logger = logging.getLogger("webrecon")

    for jwt in list(jwts)[:10]:
        try:
            parts = jwt.split('.')
            if len(parts) != 3:
                if logger:
                    logger.debug(f"Skipping malformed JWT (expected 3 parts, got {len(parts)})")
                continue

            try:
                header = json.loads(_b64url_decode(parts[0]))
            except Exception as e:
                if logger:
                    logger.debug(f"Failed to decode JWT header: {e}")
                continue

            try:
                payload = json.loads(_b64url_decode(parts[1]))
            except Exception as e:
                if logger:
                    logger.debug(f"Failed to decode JWT payload: {e}")
                continue

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


def phase_csp_analysis(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """Content-Security-Policy analysis: detects weak directives."""
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


def phase_csrf(target: str, cfg: ScanConfig, out: str, st: ScanState):
    """CSRF token presence checking in HTML forms."""
    phase = "csrf"
    if st.done(phase): return
    section("CSRF Token Presence (forms)", out)
    sess = make_session(cfg)

    # Session cookies lacking SameSite make CSRF materially easier — establish
    # that context once so we can sharpen each per-form finding.
    samesite_gap = False
    try:
        r0 = sess.get(cfg.base_url, timeout=cfg.timeout)
        for c in r0.cookies:
            ss = (c.get_nonstandard_attr('SameSite') or
                  c.get_nonstandard_attr('samesite') or '')
            if not ss:
                samesite_gap = True
                break
    except Exception:
        pass

    # Gather candidate HTML pages: base URL + a handful of discovered same-host
    # endpoints that are likely to render forms (login/account/settings/etc.).
    pages = [cfg.base_url]
    with DISCOVERED._lock:
        for u in list(DISCOVERED.urls):
            if any(k in u.lower() for k in
                   ('login', 'signin', 'register', 'account', 'settings',
                    'profile', 'password', 'contact', 'checkout', 'transfer')):
                pages.append(u)
    # De-dup, keep it bounded
    seen, page_list = set(), []
    for u in pages:
        if u not in seen:
            seen.add(u); page_list.append(u)
    page_list = page_list[:15]

    base_host = urlparse(cfg.base_url).netloc.lower()
    flagged = 0
    reported_actions: Set[str] = set()

    for page in page_list:
        try:
            r = sess.get(page, timeout=cfg.timeout)
            if r.status_code != 200 or 'html' not in r.headers.get('Content-Type', '').lower():
                continue
            if looks_like_catchall(cfg, r.text, len(r.content)):
                continue
            for fm in re.finditer(r'<form\b[^>]*>.*?</form>', r.text, re.I | re.S):
                form_html = fm.group(0)
                head = re.search(r'<form\b[^>]*>', form_html, re.I)
                head_txt = head.group(0) if head else ''
                method = 'get'
                mm = re.search(r'method=["\']?(\w+)', head_txt, re.I)
                if mm:
                    method = mm.group(1).lower()
                # Only state-changing forms matter for CSRF.
                if method != 'post':
                    continue
                # Resolve the action; only report same-origin submissions.
                am = re.search(r'action=["\']([^"\']*)["\']', head_txt, re.I)
                action = am.group(1) if am else page
                action_abs = urljoin(page, action) if action else page
                if urlparse(action_abs).netloc and urlparse(action_abs).netloc.lower() != base_host:
                    continue  # cross-origin POST target — out of our concern
                if _form_has_csrf_token(form_html):
                    continue
                # Skip pure search forms (common false positive: search has no CSRF need).
                if re.search(r'name=["\']?(q|query|search|s|keyword)["\']?', form_html, re.I) \
                        and not re.search(r'type=["\']?password', form_html, re.I):
                    continue
                key = f"{action_abs}"
                if key in reported_actions:
                    continue
                reported_actions.add(key)
                flagged += 1
                sev = Severity.MEDIUM
                extra = (" Session cookie lacks SameSite, so browsers will attach it "
                         "on cross-site requests — increasing exploitability."
                         if samesite_gap else
                         " (Session cookie SameSite may still provide partial protection — confirm.)")
                add_finding(Finding(
                    title=f"POST Form Without CSRF Token: {urlparse(action_abs).path or '/'}",
                    severity=sev,
                    description=(f"A state-changing POST form on `{page}` submits to "
                                 f"`{action_abs}` with no recognizable anti-CSRF token field."
                                 + extra +
                                 " Manually confirm the endpoint is not otherwise protected "
                                 "(custom header requirement, double-submit cookie, origin check)."),
                    evidence=f"Page: {page}\nForm action: {action_abs}\nForm head: {head_txt[:200]}",
                    recommendation=("Add a per-session/per-request anti-CSRF token to state-changing "
                                    "forms and verify it server-side. Set SameSite=Lax/Strict on session "
                                    "cookies as defence-in-depth."),
                    phase=phase), out, cfg)
        except Exception:
            continue

    if flagged == 0:
        _log(out, "> No unprotected state-changing POST forms found (or all carried tokens).")
    st.mark(phase)
