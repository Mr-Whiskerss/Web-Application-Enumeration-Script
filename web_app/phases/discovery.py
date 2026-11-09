"""
Discovery & Technology Phases

Technology detection and content discovery:
- Technology fingerprinting (WhatWeb, webanalyze)
- Tech-specific playbooks (WordPress, Drupal, etc.)
- Robots/sitemap/security.txt parsing
- Web crawling (katana)
- Content discovery (ffuf)
- Parameter discovery (arjun)
- API schema discovery (OpenAPI, Swagger, WSDL)
- Source code and VCS exposure detection
"""

import os
import re
import json
import hashlib
from typing import Dict, Optional, List
from urllib.parse import urlparse, urljoin, parse_qs, quote

# Standard relative imports for modular dependencies
from web_app.core.session import make_session
from web_app.core.findings import Finding, Severity, add_finding
from web_app.core.state import DiscoveredState, ScanState
from web_app.utils.logging import section
from web_app.utils.subprocess_runner import run_cmd
from web_app.utils.tool_check import _tool_ok
from web_app.utils.output import _log
from web_app.utils.catchall import looks_like_catchall


def yes_no(prompt: str) -> bool:
    """Prompt user for yes/no input."""
    from colorama import Fore
    while True:
        ans = input(f"{Fore.CYAN}  {prompt} (y/n): ").strip().lower()
        if ans in ('y', 'yes'): return True
        if ans in ('n', 'no'):  return False


# Global discovered state (shared across phases)
DISCOVERED = DiscoveredState()


def phase_tech_detection(target: str, cfg: "ScanConfig", out: str, st: "ScanState") -> Dict:
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


def phase_playbooks(target: str, cfg:"ScanConfig", out: str,
                    st:"ScanState", detected: Dict):
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


def phase_robots_sitemap(target: str, cfg:"ScanConfig",
                          out: str, st:"ScanState"):
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


def phase_crawler(target: str, cfg:"ScanConfig", out: str, st:"ScanState"):
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

        if urls:
            add_finding(Finding(
                title=f"Crawler: {len(urls)} URLs Discovered",
                severity=Severity.INFO,
                description=f"katana crawler discovered {len(urls)} URLs and {len(params)} unique parameters.",
                evidence='\n'.join(urls[:30]),
                phase=phase), out, cfg)
    st.mark(phase)


def phase_content_discovery(target: str, cfg:"ScanConfig", out: str, st:"ScanState"):
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


def phase_param_discovery(target: str, cfg:"ScanConfig", out: str, st:"ScanState"):
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
           "-t", str(min(cfg.threads * 2, 10))]
    # --stable forces 1 thread + 6-12s per-request delay; only viable for stealth.
    if cfg.profile == "stealth":
        cmd.append("--stable")
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


def phase_api_schema(target: str, cfg:"ScanConfig", out: str, st:"ScanState"):
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


def phase_source_exposure(target: str, cfg:"ScanConfig", out: str, st:"ScanState"):
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
