# WebRecon

**Comprehensive Web Application Reconnaissance & Enumeration**

A modular Python framework that orchestrates passive OSINT, active reconnaissance, content discovery, vulnerability probing, and reporting for web-application penetration testing.

WebRecon glues together the tools you already use — `nuclei`, `katana`, `arjun`, `ffuf`, `nmap`, `wpscan`, `wafw00f`, `subfinder` and friends — and adds its own checks for the gaps those tools leave, feeding everything into a shared discovery state so injection phases test the *real* attack surface rather than a fixed wordlist.

---

## Contents

- [Highlights](#highlights)
- [Architecture](#architecture)
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
- [Development & Testing](#development--testing)
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
- **Professional modular architecture** — clean separation of concerns with 23+ modules for easy extension, maintenance, and testing.

## Architecture

WebRecon is built on a professional modular architecture with clear separation of concerns:

```
web_app/
├── core/                    # Core functionality
│   ├── session.py          # RateLimitedSession, adaptive backoff, 429/503 handling
│   ├── state.py            # ScanState, ScopeChecker, DiscoveredState
│   ├── findings.py         # Finding dataclass, severity, deduplication
│   ├── config.py           # ConfigManager, YAML parsing, env var expansion
│   └── discovery.py        # Shared discovery state (URLs, params, endpoints)
│
├── phases/                  # 47 scanning phase functions (9 modules)
│   ├── passive.py          # DNS, certs, Wayback, Google dorks, email, subdomains, favicon, DNS security
│   ├── active.py           # Port scanning, WAF/CDN detection, vhost fuzzing
│   ├── discovery.py        # Tech detection, playbooks, robots, crawler, content/param discovery, API schema, source exposure
│   ├── http_analysis.py    # Headers, CORS, OAuth/OIDC, CSP, host header, CRLF, CSRF, JWT
│   ├── vulns.py            # SSL/TLS, Nikto, Nuclei, JS analysis, GraphQL, traversal, open redirect, SSRF, SSTI, XXE, default creds, cloud buckets, WebSockets, prototype pollution, screenshots
│   ├── http_methods.py     # HTTP methods, 403 bypass, request smuggling
│   ├── reflection_xss.py   # Reflected input and XSS context analysis
│   ├── sqli.py             # SQL injection detection (error, boolean, time-based)
│   └── dns_security.py     # SPF, DMARC, DNSSEC, CAA, AXFR validation
│
├── integrations/            # Third-party integrations
│   ├── webhook.py          # Discord/Slack webhook notifications
│   └── pentestdb.py        # PentestDB API integration
│
├── reporting/               # Finding export formats
│   ├── markdown.py         # Markdown report generation
│   ├── html.py             # Interactive HTML reports with filtering/search
│   └── json.py             # JSON export and finding diffing
│
├── utils/                   # Utilities and helpers
│   ├── subprocess_runner.py # Safe command execution with error handling
│   ├── tool_check.py       # Tool availability and permission checking
│   ├── output.py           # Thread-safe logging and formatting
│   └── helpers.py          # General utilities (validation, sanitization, normalization)
│
├── main.py                  # Orchestrator: coordinates all modules
├── config.py               # Legacy entry point (imports from main.py)
└── web_app.py              # CLI entry point (imports from main.py)

tests/                       # Comprehensive test suite (350+ tests)
├── test_core/              # Core module tests (170 tests)
├── test_utils/             # Utility module tests (138 tests)
├── test_reporting/         # Reporting module tests (24 tests)
├── conftest.py             # Pytest fixtures and configuration
└── (integration & phase tests)

configs/                     # Configuration profiles
├── config.example.yaml     # Full configuration template
├── config.aggressive.yaml  # Fast profile (threads: 10, rate: 100)
├── config.stealth.yaml     # Slow profile (threads: 2, rate: 10)
└── config.minimal.yaml     # Bare essentials
```

**Key architectural features:**
- **Thread-safe operations** — locks for concurrent logging and state management
- **Resumable scans** — atomic state persistence with per-target tracking
- **Deduplication** — MD5 hashing of (title|severity|evidence) prevents duplicate findings
- **Adaptive rate limiting** — exponential backoff for 429/503 with Retry-After header support
- **Configuration hierarchy** — CLI > explicit config > project config > user config > defaults
- **Comprehensive logging** — custom exception types with structured logging

## Capabilities

**Passive reconnaissance**
DNS / WHOIS / ASN, certificate transparency (crt.sh), Wayback URL + parameter mining, Google dorking (via Custom Search API), email harvesting, subdomain enumeration, favicon-hash pivoting, DNS posture (SPF / DMARC / DNSSEC / CAA / AXFR).

**Active reconnaissance**
Port scanning (nmap), WAF/CDN detection, virtual-host fuzzing.

**Technology & content discovery**
Tech fingerprinting with tech-specific playbooks (WordPress, Drupal, Joomla, Laravel, Spring Boot, Tomcat, Jenkins, ASP.NET/IIS), robots/sitemap/security.txt, katana crawling, OpenAPI/Swagger/WSDL schema mining, VCS/source exposure (`.git`, `.svn`, `.env`, backups), directory & hidden-parameter discovery.

**HTTP analysis**
Security-header & cookie audit, CORS misconfiguration, OAuth/OIDC enumeration, deep CSP analysis, host-header injection, CRLF injection, CSRF token presence, JWT deep analysis (`alg:none`, weak-HMAC cracking, `kid` injection, lifetime), HTTP verb tampering, 401/403 bypass.

**Vulnerability probing**
SSL/TLS, Nikto, nuclei, JavaScript secret extraction, GraphQL, path traversal, open redirect, reflected-input/XSS context analysis, differential SQLi (error / boolean / time-based), SSRF (OOB + cloud-metadata), differential SSTI, XXE (classic + blind + SOAP + SVG), default credentials, HTTP request smuggling (CL.TE / TE.CL timing), WebSocket discovery, prototype pollution.

**Infrastructure**
Cloud storage bucket checks, screenshotting.

## Installation

WebRecon is modular Python framework. Clone the repo and install the Python dependencies:

```bash
git clone https://github.com/Mr-Whiskerss/Web-Application-Enumeration-Script.git
cd Web-Application-Enumeration-Script
pip install -r requirements.txt
chmod +x web_app.py
```

**Development & testing** — install dev dependencies:

```bash
pip install -r requirements-dev.txt
pytest tests/ -v  # Run test suite (350+ tests)
```

**Optional Python packages**:

```bash
pip install mmh3          # Favicon-hash pivoting
pip install pyyaml        # YAML config support (in requirements.txt)
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

**Configuration**

| Flag | Description |
|---|---|
| `-C, --config` | YAML config file (overrides defaults, CLI args take precedence) |
| `--show-config` | Display merged configuration and exit |

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
| `<prefix>.report.html` | Filterable, dark-themed HTML report with search & severity filtering |
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

## Development & Testing

WebRecon includes a comprehensive test suite with 350+ tests across all modules:

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=web_app --cov-report=html

# Run specific test module
pytest tests/test_core/test_findings.py -v

# Run tests in parallel
pytest tests/ -n auto
```

**Test structure:**
- `tests/test_core/` — 170 tests for core modules (config, findings, state, session, discovery)
- `tests/test_utils/` — 138 tests for utility modules (helpers, subprocess, tool_check, output)
- `tests/test_reporting/` — 24 tests for reporting formats (markdown, html, json)
- `tests/test_integrations.py` — 24 tests for webhooks and PentestDB
- `tests/test_phases_sample.py` — 14 tests for sample phases

All tests use mocking to avoid external dependencies and execute in <5 seconds.

**Extending WebRecon:**
1. Add a new phase function in `web_app/phases/<phase_type>.py`
2. Import it in `web_app/main.py` and call it in the phase execution loop
3. Add unit tests in `tests/test_phases/test_<name>.py`
4. Run `pytest` to verify

See [TESTING.md](TESTING.md) for detailed testing guide.

## Design principles

- **Discovery feeds injection.** No phase tests in isolation; crawled and mined URLs/params drive the vulnerability phases.
- **Prove before you report.** Content signatures, differential payloads, and stability guards keep 200s and dynamic pages from becoming findings.
- **Aggressive is opt-in.** Anything that could cause lockouts, desync, or side effects sits behind `--no-intrusive`.
- **Graceful degradation.** Missing an external tool skips a phase and is reported — it never crashes the run.
- **Reproducible.** State files, resume, and diff mode make repeat assessments comparable.
- **Modular & maintainable.** Clean architecture with 23+ modules, comprehensive test coverage, and clear separation of concerns.

## Responsible use

WebRecon sends live, and in intrusive mode aggressive, traffic to its targets. Only run it against systems you own or are **explicitly authorised, in writing, to test**. Unauthorised scanning may be illegal in your jurisdiction and can cause disruption. Use `--scope-file` to keep testing inside agreed boundaries, prefer `--profile recon` or `--no-intrusive` when validating scope, and follow the rules of engagement for your assessment. You are responsible for how you use this tool.

## License

Released under the **GPL-3.0** license.

> Project: <https://github.com/Mr-Whiskerss/Web-Application-Enumeration-Script>
>
> Built with modular architecture, comprehensive configuration system, structured error handling, and 350+ unit tests. Designed for professional penetration testing workflows.
