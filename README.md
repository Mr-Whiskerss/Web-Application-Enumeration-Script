# WebRecon

**Comprehensive Web Application Reconnaissance & Enumeration**

A single-file Python framework that orchestrates passive OSINT, active reconnaissance, content discovery, first-party vulnerability probing, and reporting for web-application penetration testing.

WebRecon glues together the tools you already use — `nuclei`, `katana`, `arjun`, `ffuf`, `nmap`, `wpscan`, `wafw00f`, `subfinder` and friends — and adds its own checks for the gaps those tools leave, feeding everything into a shared discovery state so injection phases test the *real* attack surface rather than a fixed wordlist.

---

## Contents

- [Highlights](#highlights)
- [What's new in 3.3.0](#whats-new-in-330)
- [Capabilities](#capabilities)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Scan profiles](#scan-profiles)
- [Authenticated scanning](#authenticated-scanning)
- [Scope enforcement](#scope-enforcement)
- [Output](#output)
- [Integrations](#integrations)
- [Resume & diff](#resume--diff)
- [Design principles](#design-principles)
- [Responsible use](#responsible-use)
- [License](#license)

---

## Highlights

- **Discovery-driven** — crawler, Wayback, robots, and OpenAPI/WSDL parsing all feed a shared state (`urls`, `params`, `endpoints`) that the SQLi / XSS / SSRF / traversal phases consume. You test parameters the app actually exposes.
- **Low false-positive by design** — catch-all routing detection, differential SSTI, JSON-shape GraphQL validation, content-signature checks on exposed-file probes, and a page-stability guard on boolean SQLi.
- **Safe by default** — aggressive checks (time-based SQLi, request smuggling, default-credential submission) are gated behind `--no-intrusive`.
- **Resumable & batch-capable** — target-aware state file, `--resume`, and `-iL` list scanning with per-target outputs.
- **Reports you can hand over** — filterable dark-themed HTML, Markdown, and structured JSON suitable for import pipelines.

## What's new in 3.3.0

| Change | Type | Detail |
|---|---|---|
| **CSRF token detection** | New phase | Parses `<form>` blocks and flags same-origin **POST** forms carrying no recognizable anti-CSRF token; sharpens severity when session cookies also lack `SameSite`. Skips search forms to stay low-FP. |
| **SQLi payload encoding** | Fix (false negatives) | Injection values are now percent-encoded so payloads with spaces/quotes reach the server intact instead of being mangled or rejected. |
| **SQLi stability guard** | Fix (false positives) | Boolean-based detection now verifies the page is stable across two identical baseline requests before trusting length deltas — avoids firing on rotating tokens/timestamps/ads. |
| **Reflected-XSS transit** | Fix (false negatives) | Probe query values are encoded correctly so other parameters no longer corrupt the request and the probe reliably arrives. |
| **Open redirect coverage** | Enhancement | Adds scheme-relative (`//`), slash-less, backslash and allowlist-bypass payloads, plus body-based detection of `meta-refresh` and `window.location` redirects (not just the `Location` header). |
| **Default-credential gating** | Safety | Live credential submission (lockout/alert risk) is now behind `--no-intrusive`, consistent with the rest of the tool. |
| **`Retry-After` support** | Enhancement | The adaptive rate limiter honours a server-stated `Retry-After` (seconds or HTTP-date, capped at 120s) instead of a blind exponential curve. |

## Capabilities

**Passive reconnaissance**
DNS / WHOIS / ASN, certificate transparency (crt.sh), Wayback URL + parameter mining, Google dorking (via Custom Search API), email harvesting, subdomain enumeration, favicon-hash pivoting, DNS posture (SPF / DMARC / DNSSEC / CAA / AXFR).

**Active reconnaissance**
Port scanning (nmap), WAF/CDN detection, virtual-host fuzzing.

**Technology & content discovery**
Tech fingerprinting with tech-specific playbooks (WordPress, Drupal, Joomla, Laravel, Spring Boot, Tomcat, Jenkins, ASP.NET/IIS), robots/sitemap/security.txt, katana crawling, OpenAPI/Swagger/WSDL schema mining, VCS/source exposure (`.git`, `.svn`, `.env`, backups), directory & hidden-parameter discovery.

**HTTP analysis**
Security-header & cookie audit, CORS misconfiguration, OAuth/OIDC enumeration, deep CSP analysis, host-header injection, CRLF injection, **CSRF token presence**, JWT deep analysis (`alg:none`, weak-HMAC cracking, `kid` injection, lifetime), HTTP verb tampering, 401/403 bypass.

**Vulnerability probing**
SSL/TLS, Nikto, nuclei, JavaScript secret extraction, GraphQL, path traversal, open redirect, reflected-input/XSS context analysis, differential SQLi (error / boolean / time-based), SSRF (OOB + cloud-metadata), differential SSTI, XXE (classic + blind + SOAP + SVG), default credentials, HTTP request smuggling (CL.TE / TE.CL timing), WebSocket discovery, prototype pollution.

**Infrastructure**
Cloud storage bucket checks, screenshotting.

## Installation

WebRecon is a single script. Clone the repo and install the Python dependencies:

```bash
git clone https://github.com/Mr-Whiskerss/Web-Application-Enumeration-Script.git
cd Web-Application-Enumeration-Script
pip install requests colorama
chmod +x web_app.py
```

**Optional Python package** — enables favicon-hash pivoting:

```bash
pip install mmh3
```

### External tools

WebRecon degrades gracefully: any missing external tool is reported at the end of the run and its phase is skipped, so a partial toolset still produces a useful report. For full coverage, install:

| Tool | Purpose | Install |
|---|---|---|
| `nmap` | Port scanning | `apt install nmap` |
| `ffuf` | Content discovery | `apt install ffuf` |
| `nikto` | Web server scanning | `apt install nikto` |
| `whatweb` | Tech fingerprinting | `apt install whatweb` |
| `wafw00f` | WAF detection | `pip install wafw00f` |
| `dnsrecon` | DNS enumeration | `apt install dnsrecon` |
| `theHarvester` | Email/OSINT | `apt install theharvester` |
| `dig` | DNS lookups | `apt install dnsutils` |
| `katana` | Crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `nuclei` | Templated scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `subfinder` | Subdomain enum | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `arjun` | Hidden parameters | `pip install arjun` |
| `wpscan` | WordPress | `gem install wpscan` |
| `droopescan` | Drupal | `pip install droopescan` |
| `joomscan` | Joomla | [OWASP/joomscan](https://github.com/OWASP/joomscan) |
| `testssl.sh` | TLS analysis | `apt install testssl.sh` |
| `gowitness` | Screenshots | `go install github.com/sensepost/gowitness@latest` |
| `webanalyze` | Tech detection | `go install github.com/rverton/webanalyze/cmd/webanalyze@latest` |
| `subjack` | Subdomain takeover | `go install github.com/haccer/subjack@latest` |

On Kali/ParrotOS most of these are already present or one `apt`/`pipx` away.

## Quick start

```bash
# Full scan of a single target
./web_app.py -t example.com

# Non-interactive full scan through Burp, with OOB callbacks for SSRF/XXE
./web_app.py -t example.com --auto \
    --proxy http://127.0.0.1:8080 \
    --oob-url xxxxxx.oast.live

# Passive-only recon (no active probes)
./web_app.py -t example.com --profile recon

# Throttled, non-intrusive assessment
./web_app.py -t example.com --profile stealth --no-intrusive

# Batch scan a list of targets
./web_app.py -iL targets.txt --auto --profile stealth
```

## Usage

```
./web_app.py -t <target> [options]
```

**Core**

| Flag | Description |
|---|---|
| `-t, --target` | Target domain or IP (`host:port` also accepted) |
| `-iL, --target-list` | File of targets, one per line (`#` comments and blanks ignored) |
| `-o, --output` | Output file prefix |
| `--auto` | Skip interactive prompts; run all phases non-interactively |
| `--profile` | `recon` \| `active` \| `full` \| `stealth` (default `full`) |
| `--threads` | Parallel phase threads |
| `-v, --verbose` | Show external tool stderr |

**Network & pacing**

| Flag | Description |
|---|---|
| `--proxy` | Proxy URL, e.g. `http://127.0.0.1:8080` |
| `--user-agent` | Custom User-Agent |
| `--timeout` | HTTP timeout (seconds) |
| `--rate` | Per-phase thread/rate limit |
| `--delay` | Inter-request delay (seconds) |
| `--full-ports` | Full port scan (`-p-`) |

**Probing control**

| Flag | Description |
|---|---|
| `--oob-url` | OOB callback host for SSRF/XXE (interactsh/oast etc.) |
| `--no-intrusive` | Skip intrusive checks (time-based SQLi, request smuggling, default-cred submission, nuclei intrusive tags, Nikto) |
| `--nuclei-severity` | Nuclei severity filter (default `medium,high,critical`) |
| `--whatweb-timeout` | WhatWeb timeout, seconds (default 120) |
| `--arjun-timeout` | Arjun timeout, seconds (default 1200) |

**Authentication**

| Flag | Description |
|---|---|
| `--cookie` | Session cookie(s): `name=val; name2=val2` |
| `--header` | Extra header, repeatable: `Authorization: Bearer xyz` |
| `--auth-check-url` | URL used to verify the session is still authenticated |
| `--auth-check-text` | Text expected in the auth-check response |

**Scope, OSINT & state**

| Flag | Description |
|---|---|
| `--scope-file` | Scope file: CIDRs (v4/v6) or domains, one per line |
| `--google-api-key` / `--google-cx` | Google Custom Search credentials for dorking |
| `--google-dork-count` | Number of dorks to run (default 5) |
| `--diff` | Previous findings JSON for diff mode |
| `--resume` | Resume an interrupted scan |
| `--fresh` | Clear state and start fresh |

**Integrations & reporting**

| Flag | Description |
|---|---|
| `--webhook-url` | Discord/Slack webhook for findings at/above the threshold |
| `--webhook-threshold` | Minimum severity to notify (`INFO`…`CRITICAL`, default `HIGH`) |
| `--pentestdb-url` / `--pentestdb-token` | POST findings to a self-hosted findings DB |
| `--no-html` | Skip HTML report generation |

Run `./web_app.py --help` for the authoritative list.

## Scan profiles

| Profile | What runs |
|---|---|
| `recon` | Passive OSINT only — no active probes against the target |
| `active` | Passive + active recon + tech detection (no vulnerability scanning) |
| `full` | Everything (default) |
| `stealth` | Full coverage, throttled, intrusive external tools held back |

Combine `--no-intrusive` with any profile to suppress checks that send aggressive payloads or submit credentials.

## Authenticated scanning

Provide a session and, optionally, a liveness check so WebRecon can warn you if the session expires mid-scan. Cookies and extra headers are threaded through to katana, ffuf and nuclei as well as the first-party checks.

```bash
./web_app.py -t app.example.com --auto \
    --cookie "session=eyJhbGciOi...; csrftoken=abc123" \
    --header "Authorization: Bearer <token>" \
    --auth-check-url https://app.example.com/profile \
    --auth-check-text "Logout"
```

## Scope enforcement

Pass a scope file of CIDRs (IPv4/IPv6) and/or domains, one per line. Targets are resolved and checked against scope up front; anything out of scope is skipped rather than scanned. In batch mode, invalid or out-of-scope entries are skipped without aborting the run.

```
# scope.txt
example.com
*.example.com
203.0.113.0/24
2001:db8::/32
```

```bash
./web_app.py -iL targets.txt --scope-file scope.txt --auto
```

## Output

Each target produces a set of files under the chosen prefix:

| File | Contents |
|---|---|
| `<prefix>.md` | Full Markdown report with per-phase logs |
| `<prefix>.report.html` | Filterable, dark-themed HTML report |
| `<prefix>.findings.json` | Structured findings for import/diffing |
| `<prefix>.state.json` | Scan state for `--resume` |

The run ends with a severity summary and a **tool-availability report** that explicitly lists any external tools that were missing (and therefore phases that were skipped), so coverage gaps are visible rather than silent.

## Integrations

**Webhooks** — push findings at or above `--webhook-threshold` to a Discord or Slack incoming webhook (auto-detected from the URL):

```bash
./web_app.py -t example.com --auto \
    --webhook-url https://discord.com/api/webhooks/... \
    --webhook-threshold HIGH
```

**Findings DB** — POST each finding to a self-hosted instance:

```bash
./web_app.py -t example.com --auto \
    --pentestdb-url http://127.0.0.1:5000 \
    --pentestdb-token <bearer>
```

## Resume & diff

```bash
# Resume an interrupted scan (state is target-aware)
./web_app.py -t example.com --resume

# Compare this run against a previous export (new / resolved / unchanged)
./web_app.py -t example.com --auto --diff example.findings.json
```

## Design principles

- **Discovery feeds injection.** No phase tests in isolation; crawled and mined URLs/params drive the vulnerability phases.
- **Prove before you report.** Content signatures, differential payloads, and stability guards keep 200s and dynamic pages from becoming findings.
- **Aggressive is opt-in.** Anything that could cause lockouts, desync, or side effects sits behind `--no-intrusive`.
- **Graceful degradation.** Missing an external tool skips a phase and is reported — it never crashes the run.
- **Reproducible.** State files, resume, and diff mode make repeat assessments comparable.

## Responsible use

WebRecon sends live, and in intrusive mode aggressive, traffic to its targets. Only run it against systems you own or are **explicitly authorised, in writing, to test**. Unauthorised scanning may be illegal in your jurisdiction and can cause disruption. Use `--scope-file` to keep testing inside agreed boundaries, prefer `--profile recon` or `--no-intrusive` when validating scope, and follow the rules of engagement for your assessment. You are responsible for how you use this tool.

## License

Released under the **GPL-3.0** license.

> Project: <https://github.com/Mr-Whiskerss/Web-Application-Enumeration-Script>
