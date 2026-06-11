# WebRecon

> Comprehensive web application reconnaissance and vulnerability enumeration framework

**WebRecon** is a single-file Python tool that automates the web-application phase of an external or internal pentest — passive OSINT, active recon, content discovery, technology fingerprinting, vulnerability probing, and reporting — with resumable state, authenticated scanning, and multi-format output.

It's a glue layer around the tools you already use (nuclei, katana, arjun, ffuf, nmap, wpscan, wafw00f, subfinder, etc.) plus ~4200 lines of first-party Python checks covering the gaps those tools leave: JWT deep analysis, CORS, security headers, SSRF/SSTI/CRLF/host-header injection, cloud-metadata probing, default credentials, favicon-hash pivoting, JS secret extraction, **differential SQLi, reflected-XSS context analysis, HTTP request smuggling, verb tampering, 401/403 bypass, deep CSP analysis, OpenAPI/Swagger/WSDL schema mining, VCS/source exposure, WebSocket discovery, prototype pollution, DNS posture (SPF/DMARC/DNSSEC/CAA/AXFR)**, and more.

---

## What's new in v3.2.0

Eleven new first-party phases, all built in the existing idiom — catch-all/false-positive suppression, fed by (and feeding) the shared discovery state, and gated by the same scan profiles and `--no-intrusive` switch:

- **DNS security posture** — SPF / DMARC / DNSSEC / CAA review + zone-transfer (AXFR) attempt *(Phase 1)*
- **API schema discovery** — parses OpenAPI / Swagger / WSDL and feeds discovered endpoints + parameters into every downstream injection phase *(Phase 3)*
- **Source / VCS / config exposure** — `.git`, `.svn`, `.hg`, `.DS_Store`, `.env`, `.htpasswd`, backup / swap files (each gated on a content signature) *(Phase 3)*
- **HTTP methods & verb tampering** — dangerous verbs, TRACE/XST, live PUT upload test, verb-based auth bypass *(Phase 4)*
- **401 / 403 bypass** — path-normalisation and header-override techniques *(Phase 4)*
- **Deep CSP analysis** — flags `unsafe-inline`, `unsafe-eval`, wildcard sources, missing `object-src` / `base-uri` / `frame-ancestors` *(Phase 4)*
- **SQL injection** — error-based + boolean-differential + double-confirmed time-based blind *(Phase 5)*
- **Reflected input / XSS context probe** — non-executing differential canary with HTML / attribute / JS / JSON context classification *(Phase 5)*
- **HTTP request smuggling** — timing-based CL.TE / TE.CL desync detection *(Phase 5)*
- **WebSocket discovery** — endpoint enumeration + cross-origin handshake (CSWSH) check *(Phase 5)*
- **Prototype pollution** — `__proto__` gadget probes via query string and JSON body *(Phase 5)*

Plus: per-cookie `HttpOnly` / `SameSite` precision (now inspects each cookie's own attributes, and flags `SameSite=None` without `Secure`), and an ASP.NET / IIS technology playbook.

The intrusive subset (live PUT upload, time-based SQLi, request smuggling) only runs when intrusive checks are enabled, so `--profile recon` / `--profile stealth` / `--no-intrusive` stay safe.

---

## Features

### Passive reconnaissance
- DNS, WHOIS, ASN lookups (domain-age flag, IPv6 presence check)
- **DNS security posture** — SPF, DMARC (policy-enforcement check), DNSSEC, CAA, plus an AXFR zone-transfer attempt against each authoritative nameserver
- Certificate transparency (crt.sh)
- Wayback Machine URL + parameter mining — parameters are fed into later fuzzing phases
- Google dork URL generation (+ optional Custom Search API automation)
- Email harvesting (theHarvester)

### Active reconnaissance
- Subdomain enumeration (subfinder) with scope-aware filtering
- Subdomain takeover detection (subjack + in-tree fingerprints covering S3, GitHub Pages, Heroku, Azure, Shopify, Fastly, Surge, Bitbucket)
- Virtual-host fuzzing (ffuf)
- Port scanning (nmap, web-focused default / `--full-ports` for all)
- WAF / CDN fingerprinting (wafw00f + header-based detection of Cloudflare, CloudFront, Akamai, Fastly, Azure CDN, Sucuri)
- Favicon hash (mmh3 for Shodan pivoting + SHA-256 fallback)

### Technology & content discovery
- Technology detection (whatweb, webanalyze)
- Tech-specific playbooks — kicks off **only** for detected stacks:
  - **WordPress** → wpscan (plugin / user enum)
  - **Drupal** → droopescan
  - **Joomla** → joomscan
  - **Laravel** → `.env`, Telescope, Ignition, debugbar, Horizon probes
  - **Spring Boot** → actuator sweep (env, heapdump, mappings, trace, etc.)
  - **Tomcat** → manager / host-manager / examples
  - **Jenkins** → `/script`, `/manage`, `/asynchPeople/`
  - **ASP.NET / IIS** → trace.axd, elmah.axd, web.config, FrontPage extensions, App_Data/bin/App_Code probing (with per-endpoint confirmation strings)
- **API schema discovery** — OpenAPI / Swagger (JSON spec + UI), WSDL/SOAP; parsed endpoints and parameters are pushed into the shared discovery state so SQLi / XSS / SSRF / traversal phases test the **real API surface**
- **Source / VCS / config exposure** — `.git/HEAD` + `.git/config`, `.svn`, `.hg`, `.DS_Store`, `.env`, `.htpasswd`, `phpinfo`, `server-status` / `server-info`, Docker artefacts, and backup / editor-swap files — every hit requires a content signature to avoid catch-all 200 false positives
- robots.txt, sitemap.xml, security.txt, well-known endpoints
- URL crawling (katana) — feeds URLs + params into downstream phases
- Content discovery (ffuf) — general + admin-panel wordlist
- Hidden parameter discovery (Arjun) — runs against base URL + crawled endpoints

### HTTP analysis
- Security header audit (HSTS, CSP, X-Frame-Options, X-CTO, Referrer-Policy, Permissions-Policy)
- **Deep CSP analysis** — parses the policy and flags `unsafe-inline` (without nonce/hash/strict-dynamic), `unsafe-eval`, wildcard / broad-scheme sources, and missing `object-src` / `base-uri` / `frame-ancestors`
- Cookie audit (per-cookie Secure, HttpOnly, SameSite — including `SameSite=None` without `Secure`)
- Information disclosure (Server, X-Powered-By, X-AspNet-Version)
- CORS misconfiguration (origin reflection, wildcard + credentials)
- **Host header injection** (Host, X-Forwarded-Host, X-Host canary reflection)
- **CRLF injection** (common + crawler-discovered parameters)
- **HTTP methods & verb tampering** — OPTIONS enumeration, TRACE / XST, live PUT upload test (auto-cleaned up, intrusive only), and verb-based auth bypass against protected paths
- **401 / 403 bypass** — trailing slash / dot, double slash, `%2e`, `..;/`, encoded slash, case mutation, and `X-Original-URL` / `X-Rewrite-URL` / client-IP header overrides, confirmed by content-length divergence from the deny page
- OAuth / OIDC endpoint discovery (`.well-known/*`, JWKS, token endpoints)
- **JWT deep analysis**:
  - `alg:none` acceptance
  - Weak-HMAC cracking (12-secret wordlist — `secret`, `password`, `changeme`, etc.)
  - `kid` header injection / path-traversal hints
  - Missing / excessive `exp` claims

### Vulnerability scanning
- **Nuclei** — CVE / misconfig templates with severity filter and intrusive-tag gating
- **SQL injection** — error-based (DB error signatures), boolean-based differential (TRUE matches baseline / FALSE diverges), and double-confirmed time-based blind (MySQL `SLEEP`, MSSQL `WAITFOR`, PostgreSQL `pg_sleep`); time-based confirmation is intrusive only
- **Reflected input / XSS context probe** — injects a unique, **non-executing** marker plus raw `< > " '` to see which survive unencoded and in what context (HTML body / attribute / inside `<script>` / JSON); one report per parameter
- **SSRF** — OOB-based with unique markers per parameter + cloud metadata sweep (AWS, GCP, DigitalOcean, file://)
- **SSTI** — Jinja2, Twig, FreeMarker, ERB, Thymeleaf, Razor with arithmetic canary
- **XXE** — classic external entity, blind parameter-entity via external DTD, SOAP envelope, SVG-embedded
- **HTTP request smuggling** — timing-based CL.TE and TE.CL desync detection over a raw socket (intrusive; skipped under `--proxy`; flagged for manual confirmation)
- **Path traversal** — common encodings + per-parameter testing
- **Open redirect** — standard + crawler-discovered redirect-like params
- **Prototype pollution** — `__proto__` gadget via query string and JSON body, detecting server-side faults and reflected gadgets
- **WebSocket discovery** — endpoint extraction from HTML/JS + Upgrade-handshake probing with a foreign Origin to surface missing origin validation (CSWSH)
- **Default credentials** — Tomcat (Basic), Jenkins, WordPress (form), Grafana-style (JSON) — explicit success/failure text checks, no false positives from generic 200s
- **JS secret extraction** — AWS access keys, API keys, tokens, JWTs, private keys, Google/Slack/GitHub tokens, Basic-auth-in-URL, hardcoded passwords, internal IPs
- GraphQL endpoint detection + introspection probe
- SSL/TLS analysis (testssl.sh)
- Nikto (optional, gated)

### Infrastructure
- Cloud bucket enumeration (S3, GCS, Azure Blob — 12 name-mutation patterns)
- Headless screenshots (gowitness)

### Pentester features
- **Resumable scans** (JSON state file — survives Ctrl-C / reboot)
- **Scope enforcement** (IPv4 + IPv6 CIDRs + domains, with DNS-resolution scope check)
- **Scan profiles**: `recon` / `active` / `full` / `stealth`
- **Authenticated scanning** — cookies, arbitrary headers (Bearer, API keys), session revalidation
- **API-aware** — discovered schemas expand the attack surface tested by every injection phase
- **Adaptive rate limiting** — backs off exponentially on 429/503, global across all threads
- **Proxy-aware** — Burp, ZAP, mitmproxy (HTTP + SOCKS)
- **Diff mode** — delta findings against a previous scan
- **Webhook notifications** — Discord / Slack (auto-detected), configurable severity threshold
- **PentestDB integration** — POST findings to your self-hosted pentest findings database
- **Output formats** — Markdown, filterable HTML, JSON

---

## Installation

```bash
# Clone
git clone https://github.com/Mr-Whiskerss/Web-Application-Enumeration-Script.git
cd Web-Application-Enumeration-Script

# Python dependencies (core)
pip install -r requirements.txt          # requests, urllib3, colorama

# Optional Python deps (one extra feature each)
pip install mmh3 arjun                    # favicon hash + hidden-param discovery

# Go tools (install what you plan to use)
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
nuclei -update-templates

# System packages (Debian / Ubuntu example)
sudo apt install nmap nikto whatweb ffuf wafw00f theharvester dnsrecon \
                 whois dnsutils testssl.sh
# dnsutils provides `dig`, used by the DNS security-posture phase

# CMS-specific (install as needed)
sudo gem install wpscan                       # WordPress
pip install droopescan                        # Drupal
# joomscan → https://github.com/OWASP/joomscan
# gowitness → https://github.com/sensepost/gowitness
```

WebRecon degrades gracefully — any missing external tool causes its phase to log a warning and skip. The scan continues. The new injection, exposure, CSP, methods, smuggling, WebSocket and prototype-pollution phases are pure first-party Python and need no external tools; the DNS-posture phase only needs `dig`.

---

## Quick start

```bash
# Full scan, interactive prompts
./web_app.py -t example.com

# Fully automated, through Burp, with OOB callback
./web_app.py -t example.com --auto \
  --proxy http://127.0.0.1:8080 \
  --oob-url abc.oast.live

# Authenticated scan
./web_app.py -t app.example.com --auto \
  --cookie "session=abc123; csrf=xyz" \
  --auth-check-url https://app.example.com/account \
  --auth-check-text "Sign out"

# Passive-only OSINT pass
./web_app.py -t example.com --profile recon --auto

# Low-and-slow
./web_app.py -t example.com --profile stealth --auto

# Batch scan a file of targets (one per line)
./web_app.py -iL targets.txt --auto
```

---

## Scan profiles

| Profile   | Phases run                               | Rate / threads   | Intrusive |
|-----------|------------------------------------------|------------------|-----------|
| `recon`   | Phase 1 only (passive)                   | default          | disabled  |
| `active`  | Phases 1–4 (passive + active + HTTP)     | default          | enabled   |
| `full`    | All phases *(default)*                   | default          | enabled   |
| `stealth` | All phases                               | ≤10 req/s, 2 thr | disabled  |

`--no-intrusive` can be applied to any profile to skip Nikto, nuclei-tagged `intrusive` / `fuzz` / `dos` templates, **and the intrusive-only checks added in v3.2.0** (live PUT upload test, time-based SQLi confirmation, HTTP request smuggling). Error-based and boolean-based SQLi, reflected-XSS, verb tampering and 403-bypass remain active — they are non-destructive.

---

## Authentication

Authenticated scanning supports cookies, arbitrary headers, and session revalidation:

```bash
./web_app.py -t app.example.com --auto \
  --cookie "session=abc123" \
  --header "Authorization: Bearer eyJhbGc..." \
  --header "X-API-Key: deadbeef" \
  --auth-check-url https://app.example.com/me \
  --auth-check-text "your_username"
```

The auth-check runs at scan start — it hits `--auth-check-url` and asserts `--auth-check-text` is in the response. If the session is invalid, you get a warning (the scan continues — the warning is yours to act on).

Cookies and headers are threaded through to **katana**, **arjun**, **ffuf**, and **nuclei** where those tools support the relevant flags.

---

## Examples

**Pentest iteration with resume**
```bash
./web_app.py -t client.corp --auto --oob-url $(interactsh-client -json | jq -r .url)
# [Ctrl-C / reboot / sleep]
./web_app.py -t client.corp --resume
```

**Retest with diff report**
```bash
./web_app.py -t client.corp --auto --diff previous_scan.findings.json
# Summary section will include New / Resolved / Unchanged
```

**Discord alerts for HIGH+ findings**
```bash
./web_app.py -t client.corp --auto \
  --webhook-url https://discord.com/api/webhooks/.../... \
  --webhook-threshold HIGH
```

**Auto-push findings to self-hosted PentestDB**
```bash
./web_app.py -t client.corp --auto \
  --pentestdb-url http://pi.lan:5000 \
  --pentestdb-token "$PENTESTDB_TOKEN"
```

**Bug bounty — wide nuclei, skip Nikto, full ports**
```bash
./web_app.py -t target.bb --auto \
  --full-ports \
  --nuclei-severity low,medium,high,critical \
  --no-intrusive
```

**Batch scanning — a file of targets**
```bash
cat > targets.txt <<'EOF'
# one target per line — domains, IPs, or host:port
app.client.corp
10.0.0.10
api.client.corp:8443
EOF

./web_app.py -iL targets.txt --auto
```
Each target is scanned in turn and gets its **own** output set, prefixed with the
sanitised target name (e.g. `webrecon_10.0.0.10.md`, `webrecon_app.client.corp.report.html`),
so nothing overwrites. State, findings, discovered URLs/params and dedup are reset
between targets — results never bleed across the batch — and a combined severity
summary is printed at the end. Blank lines and `#` comments (including inline) are
ignored; invalid or out-of-scope entries are skipped with a warning rather than
aborting the run. Use `-o <prefix>` to change the per-target prefix, and combine with
`--scope-file` to hard-enforce scope across the whole list.

> Batch input expects one host per line. CIDR ranges (`10.0.0.0/24`) and IPv6 literals
> aren't expanded by the validator — pre-expand ranges first, e.g.
> `nmap -sL -n 10.0.0.0/24 | awk '/report for/{print $NF}' > targets.txt`.

**Scope-locked engagement**
```bash
cat > scope.txt <<'EOF'
10.0.0.0/8
192.168.0.0/16
2001:db8::/32
client.corp
EOF

./web_app.py -t client.corp --auto --scope-file scope.txt
# Out-of-scope subdomains discovered during enum are filtered automatically
```

**Internal engagement via SSH tunnel + Burp**
```bash
ssh -D 1080 jumpbox.client.corp &
./web_app.py -t internal.app.client.corp --auto \
  --proxy socks5://127.0.0.1:1080
# Note: the request-smuggling phase auto-skips under --proxy (it needs a raw socket)
```

---

## CLI reference

Run `./web_app.py --help` for the full list.

| Flag                       | Purpose                                                     |
|----------------------------|-------------------------------------------------------------|
| `-t, --target`             | Target (domain / IP / host:port)                            |
| `-o, --output`             | Output prefix (default `webrecon`)                          |
| `-iL, --target-list`       | File of targets, one per line — batch mode                  |
| `--auto`                   | Skip all interactive prompts                                |
| `--profile`                | `recon` / `active` / `full` / `stealth`                     |
| `--proxy`                  | HTTP / SOCKS proxy                                          |
| `--oob-url`                | Out-of-band callback host (interactsh) for XXE/SSRF         |
| `--scope-file`             | Scope enforcement file (CIDRs v4/v6 + domains)              |
| `--cookie`                 | Session cookie(s)                                           |
| `--header`                 | Extra request header (repeatable)                           |
| `--auth-check-url/-text`   | Session revalidation before scan                            |
| `--webhook-url`            | Discord / Slack webhook (auto-detected)                     |
| `--webhook-threshold`      | Minimum severity to notify (default `HIGH`)                 |
| `--pentestdb-url/-token`   | Self-hosted PentestDB integration                           |
| `--diff`                   | Previous findings JSON (delta report)                       |
| `--resume` / `--fresh`     | Resume interrupted / clear state                            |
| `--full-ports`             | Full TCP port scan (`-p-`)                                  |
| `--no-intrusive`           | Skip Nikto, nuclei intrusive templates, live PUT, time-based SQLi, smuggling |
| `--nuclei-severity`        | Nuclei severity filter                                      |
| `--google-api-key/-cx`     | Google Custom Search (automated dorking)                    |
| `--threads`                | Parallel phase threads                                      |
| `--rate` / `--delay`       | Per-phase rate limit / inter-request delay                  |
| `--no-html`                | Skip HTML report                                            |
| `-v, --verbose`            | Show tool stderr                                            |

---

## Output

A single scan produces:

| File                          | Contents                                                    |
|-------------------------------|-------------------------------------------------------------|
| `<prefix>.md`                 | Markdown report — full tool output + findings               |
| `<prefix>.report.html`        | Self-contained filterable HTML report (no server required)  |
| `<prefix>.findings.json`      | Structured findings (JSON list of `Finding` objects)        |
| `<prefix>.state.json`         | Resume state (phase checkpoints)                            |

In **batch mode** (`-iL`) the prefix becomes `<prefix>_<target>`, so every target
produces its own independent `.md` / `.report.html` / `.findings.json` / `.state.json`
set and `--resume` works per target.

Findings are categorised:

| Severity   | When used                                                                          |
|------------|------------------------------------------------------------------------------------|
| `CRITICAL` | RCE, auth bypass, default creds, SSRF→metadata, SSTI, SQLi (error/time-based), PUT upload, exposed `.env` |
| `HIGH`     | Subdomain takeover, exposed admin, LFI, JWT weak secret, boolean SQLi, reflected unescaped `<>`, verb / 403 bypass, request smuggling, VCS exposure |
| `MEDIUM`   | CORS misconfig, weak CSP, weak cookies, open redirect, TRACE/XST, CSWSH, host-header injection, prototype pollution |
| `LOW`      | Missing low-impact headers, information disclosure, dangerous methods advertised   |
| `INFO`     | Enumerated data (subdomains, URLs, tech stack, favicon hash, API endpoints, WebSocket endpoints) |

The HTML report supports severity filtering and full-text search — drop it in a browser.

---

## Architecture

WebRecon organises checks into six phases, executed in order. Earlier-phase discoveries feed later phases via a thread-safe `DiscoveredState` store:

```
Phase 1 — Passive recon      (DNS, DNS-security, crt.sh, wayback, dorks,
                              subdomains, favicon)
                                         │
                                         ▼ feeds URLs + params
Phase 2 — Active recon       (nmap, wafw00f, vhost fuzzing)
                                         │
                                         ▼
Phase 3 — Tech & content     (whatweb, playbooks, robots, katana,
                              API schema, source/VCS exposure, ffuf, arjun)
                                         │
                                         ▼ feeds URLs + params + endpoints
Phase 4 — HTTP analysis      (headers, CSP, cors, host-header, crlf, oidc,
                              jwt, http-methods/verb-tamper, 401/403 bypass)
                                         │
                                         ▼
Phase 5 — Vulnerability      (ssl, nuclei, js, graphql, lfi, redirect,
                              reflected-xss, sqli, websocket, proto-pollution,
                              ssrf, ssti, xxe, default-creds, smuggling)
                                         │
                                         ▼
Phase 6 — Infrastructure     (cloud buckets, screenshots)
```

Parameters and endpoints harvested by the crawler, wayback mining **and parsed API schemas** feed the SQLi / XSS / SSRF / SSTI / CRLF / path-traversal / open-redirect / XXE / prototype-pollution probes, so those phases test the target's actual attack surface rather than a hardcoded generic parameter list.

Every check that infers "a path exists because it returned 200" first runs through catch-all detection (a random unlikely path is probed at scan start, and its response signature is compared against), and content-dependent findings (VCS files, API specs, SQLi, reflected XSS) additionally require a confirming signature or differential — so SPA / CDN / WAF catch-all routing does not generate false positives.

---

## Dependencies

**Required (Python)** — `requests`, `urllib3`, `colorama`

**Optional** — each missing tool disables one feature and is logged, nothing else:

| Dependency    | Feature                                    |
|---------------|--------------------------------------------|
| `mmh3`        | Shodan-compatible favicon hash             |
| `dig` (dnsutils) | DNS security posture (SPF/DMARC/DNSSEC/CAA/AXFR) |
| `nmap`        | Port scanning                              |
| `nuclei`      | Template-based vulnerability scanning      |
| `katana`      | Crawling (feeds later phases)              |
| `arjun`       | Hidden parameter discovery                 |
| `subfinder`   | Subdomain enumeration                      |
| `subjack`     | Subdomain takeover scan                    |
| `ffuf`        | Content discovery / vhost fuzzing          |
| `whatweb`     | Technology fingerprinting                  |
| `webanalyze`  | Technology fingerprinting (alt)            |
| `wafw00f`     | WAF detection                              |
| `wpscan`      | WordPress deep-dive                        |
| `droopescan`  | Drupal deep-dive                           |
| `joomscan`    | Joomla deep-dive                           |
| `nikto`       | Legacy vulnerability scanner               |
| `testssl`     | SSL/TLS analysis                           |
| `theHarvester`| Email harvesting                           |
| `dnsrecon`    | DNS reconnaissance                         |
| `gowitness`   | Screenshots                                |

The SQLi, reflected-XSS, CSP, HTTP-methods, 401/403-bypass, request-smuggling, WebSocket, prototype-pollution, source-exposure and API-schema phases are pure first-party Python and have **no external tool dependency**.

---

## Ethical use

WebRecon is a penetration-testing tool. **Only run it against systems you own or have explicit, written authorisation to test.** The intrusive checks (PUT upload, time-based SQLi, request smuggling) actively modify state or stress the target — keep them disabled with `--no-intrusive` unless your rules of engagement permit them. Unauthorised access to computer systems is a criminal offence in most jurisdictions (Computer Misuse Act 1990, Computer Fraud and Abuse Act, etc.). The author accepts no responsibility for misuse.

---

## License

GPL-3.0 — see [LICENSE](LICENSE).

---

## Credits

WebRecon stands on the shoulders of:

- [ProjectDiscovery](https://github.com/projectdiscovery) — nuclei, katana, subfinder, interactsh
- [Arjun](https://github.com/s0md3v/Arjun) — s0md3v
- [ffuf](https://github.com/ffuf/ffuf) — joohoi
- [wpscan](https://wpscan.com) — WPScan team
- [wafw00f](https://github.com/EnableSecurity/wafw00f) — EnableSecurity
- [OWASP JoomScan](https://github.com/OWASP/joomscan), [droopescan](https://github.com/SamJoan/droopescan)
- and the countless open-source security projects this framework orchestrates.
