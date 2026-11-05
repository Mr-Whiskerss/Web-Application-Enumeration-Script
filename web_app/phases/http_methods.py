"""
HTTP Methods & Access Control Bypass Phases

Testing HTTP methods and access control:
- HTTP method enumeration (OPTIONS, TRACE, etc.)
- Verb-based authentication bypass
- 401/403 access control bypass techniques (path normalization, header tricks)
- HTTP request smuggling detection (CL.TE, TE.CL timing)
"""

import os
import hashlib
import socket
import time
from urllib.parse import urlparse

from web_app.core.session import make_session
from web_app.core.finding import Finding, Severity, add_finding
from web_app.core.discovery import DISCOVERED
from web_app.core.state import section


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


def phase_http_methods(target: str, cfg, out: str, st):
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
            from web_app.core.logging import _log
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
        from web_app.core.logging import _log
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


def phase_403_bypass(target: str, cfg, out: str, st):
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


def phase_request_smuggling(target: str, cfg, out: str, st):
    """Timing-based HTTP/1.1 desync detection (CL.TE and TE.CL). A vulnerable
    front/back-end pair will stall waiting for body bytes that never arrive,
    producing a measurable delay versus a well-formed baseline. Intrusive."""
    phase = "request_smuggling"
    if st.done(phase): return
    section("HTTP Request Smuggling (timing probe)", out)
    if cfg.no_intrusive:
        from web_app.core.logging import _log
        _log(out, "> Request smuggling skipped (--no-intrusive)."); st.mark(phase); return
    if cfg.proxy:
        from web_app.core.logging import _log
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
        from web_app.core.logging import _log
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
        from web_app.core.logging import _log
        _log(out, f"> Smuggling probe failed (likely benign): {e}")
    st.mark(phase)
