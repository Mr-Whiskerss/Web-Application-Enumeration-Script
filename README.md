# WebRecon

> Comprehensive web application reconnaissance and vulnerability enumeration framework

**WebRecon** is a single-file Python tool that automates the web-application phase of an external or internal pentest — passive OSINT, active recon, content discovery, technology fingerprinting, vulnerability probing, and reporting — with resumable state, authenticated scanning, and multi-format output.

It's a glue layer around the tools you already use (nuclei, katana, arjun, ffuf, nmap, wpscan, wafw00f, subfinder, etc.) plus ~2800 lines of first-party Python checks covering the gaps those tools leave: JWT deep analysis, CORS, security headers, SSRF/SSTI/CRLF/host-header injection, cloud-metadata probing, default credentials, favicon-hash pivoting, JS secret extraction, and more.

---

## Features

### Passive reconnaissance
- DNS, WHOIS, ASN lookups (domain-age flag, IPv6 presence check)
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
- robots.txt, sitemap.xml, security.txt, well-known endpoints
- URL crawling (katana) — feeds URLs + params into downstream phases
- Content discovery (ffuf) — general + admin-panel wordlist
- Hidden parameter discovery (Arjun) — runs against base URL + crawled endpoints

### HTTP analysis
- Security header audit (HSTS, CSP, X-Frame-Options, X-CTO, Referrer-Policy, Permissions-Policy)
- Cookie audit (Secure, HttpOnly, SameSite)
- Information disclosure (Server, X-Powered-By, X-AspNet-Version)
- CORS misconfiguration (origin reflection, wildcard + credentials)
- **Host header injection** (Host, X-Forwarded-Host, X-Host canary reflection)
- **CRLF injection** (common + crawler-discovered parameters)
- OAuth / OIDC endpoint discovery (`.well-known/*`, JWKS, token endpoints)
- **JWT deep analysis**:
  - `alg:none` acceptance
  - Weak-HMAC cracking (12-secret wordlist — `secret`, `password`, `changeme`, etc.)
  - `kid` header injection / path-traversal hints
  - Missing / excessive `exp` claims

### Vulnerability scanning
- **Nuclei** — CVE / misconfig templates with severity filter and intrusive-tag gating
- **SSRF** — OOB-based with unique markers per parameter + cloud metadata sweep (AWS, GCP, DigitalOcean, file://)
- **SSTI** — Jinja2, Twig, FreeMarker, ERB, Thymeleaf, Razor with arithmetic canary
- **XXE** — classic external entity, blind parameter-entity via external DTD, SOAP envelope, SVG-embedded
- **Path traversal** — common encodings + per-parameter testing
- **Open redirect** — standard + crawler-discovered redirect-like params
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
git clone https://github.com/Mr-Whiskerss/WebRecon.git
cd WebRecon

# Python dependencies
pip install requests colorama tqdm mmh3 arjun

# Go tools (install what you plan to use)
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
nuclei -update-templates

# System packages (Debian / Ubuntu example)
sudo apt install nmap nikto whatweb ffuf wafw00f theharvester dnsrecon \
                 whois dnsutils testssl.sh

# CMS-specific (install as needed)
sudo gem install wpscan                       # WordPress
pip install droopescan                        # Drupal
# joomscan → https://github.com/OWASP/joomscan
# gowitness → https://github.com/sensepost/gowitness
```

WebRecon degrades gracefully — any missing external tool causes its phase to log a warning and skip. The scan continues.

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
```

---

## Scan profiles

| Profile   | Phases run                               | Rate / threads   | Intrusive |
|-----------|------------------------------------------|------------------|-----------|
| `recon`   | Phase 1 only (passive)                   | default          | disabled  |
| `active`  | Phases 1–4 (passive + active + HTTP)     | default          | enabled   |
| `full`    | All phases *(default)*                   | default          | enabled   |
| `stealth` | All phases                               | ≤10 req/s, 2 thr | disabled  |

`--no-intrusive` can be applied to any profile to skip Nikto and nuclei-tagged `intrusive` / `fuzz` / `dos` templates.

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
```

---

## CLI reference

Run `./web_app.py --help` for the full list.

| Flag                       | Purpose                                                     |
|----------------------------|-------------------------------------------------------------|
| `-t, --target`             | Target (domain / IP / host:port)                            |
| `-o, --output`             | Output prefix (default `webrecon`)                          |
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
| `--no-intrusive`           | Skip Nikto + nuclei intrusive templates                     |
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

Findings are categorised:

| Severity   | When used                                                          |
|------------|--------------------------------------------------------------------|
| `CRITICAL` | Confirmed RCE, auth bypass, default creds, SSRF→metadata, SSTI     |
| `HIGH`     | Subdomain takeover, exposed admin, LFI, JWT weak secret            |
| `MEDIUM`   | CORS misconfig, missing CSP, weak cookies, open redirect           |
| `LOW`      | Missing low-impact headers, information disclosure                 |
| `INFO`     | Enumerated data (subdomains, URLs, tech stack, favicon hash)       |

The HTML report supports severity filtering and full-text search — drop it in a browser.

---

## Architecture

WebRecon organises checks into six phases, executed in order. Earlier-phase discoveries feed later phases via a thread-safe `DiscoveredState` store:

```
Phase 1 — Passive recon      (DNS, crt.sh, wayback, dorks, subdomains, favicon)
                                         │
                                         ▼ feeds URLs + params
Phase 2 — Active recon       (nmap, wafw00f, vhost fuzzing)
                                         │
                                         ▼
Phase 3 — Tech & content     (whatweb, playbooks, robots, katana, ffuf, arjun)
                                         │
                                         ▼ feeds URLs + params + endpoints
Phase 4 — HTTP analysis      (headers, cors, host-header, crlf, oidc, jwt)
                                         │
                                         ▼
Phase 5 — Vulnerability      (ssl, nuclei, js, graphql, lfi, redirect,
                              ssrf, ssti, xxe, default-creds)
                                         │
                                         ▼
Phase 6 — Infrastructure     (cloud buckets, screenshots)
```

Parameters harvested by the crawler and wayback mining feed SSRF / SSTI / CRLF / path-traversal / open-redirect / XXE probes, so those phases test the target's actual attack surface rather than a hardcoded generic parameter list.

---

## Dependencies

**Required (Python)** — `requests`, `colorama`, `tqdm`

**Optional** — each missing tool disables one feature and is logged, nothing else:

| Dependency    | Feature                                    |
|---------------|--------------------------------------------|
| `mmh3`        | Shodan-compatible favicon hash             |
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

---

## Ethical use

WebRecon is a penetration-testing tool. **Only run it against systems you own or have explicit, written authorisation to test.** Unauthorised access to computer systems is a criminal offence in most jurisdictions (Computer Misuse Act 1990, Computer Fraud and Abuse Act, etc.). The author accepts no responsibility for misuse.

---

## License

MIT

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
