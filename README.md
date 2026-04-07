# Web Application Enumeration Script. 

> Comprehensive web application enumeration and vulnerability discovery tool for authorised penetration testing engagements.

---

## Legal Disclaimer

This tool is intended for use against systems you own or have **explicit written authorisation** to test. Unauthorised use against systems you do not have permission to test is illegal and unethical. The author accepts no liability for misuse.

---

## Features

### Architecture
- **Parallel execution** — independent phases run concurrently via `ThreadPoolExecutor`, significantly reducing total scan time
- **Resumable scans** — state is written after each phase; interrupted scans can be resumed with `--resume`
- **Scope enforcement** — provide a scope file of CIDRs and/or domains; any out-of-scope target is hard-blocked before any traffic is sent
- **Structured findings** — every finding is written to a `.findings.json` file with severity, evidence, and recommendation fields, ready to import into a findings database
- **Diff mode** — compare findings against a previous scan's JSON to surface new and resolved issues
- **Proxy support** — all native HTTP calls route through a specified proxy (e.g. Burp Suite) via `--proxy`
- **Custom User-Agent** — configurable UA string applied to all requests
- **`shell=False` throughout** — no subprocess injection risk; inputs are validated and sanitised before use

### Phase 1 — Passive Reconnaissance
| Check | Tool/Method |
|---|---|
| DNS enumeration | `nslookup`, `dnsrecon` |
| WHOIS (flags recently registered domains) | `whois` |
| ASN & IP range lookup | `ipinfo.io` API |
| IPv6 address detection & probing | `socket` |
| Certificate transparency mining | `crt.sh` CDX API |
| Wayback Machine URL mining | Wayback CDX API |
| Google dork generation | URL generation + optional Google Custom Search API |
| Email harvesting | `theHarvester` |
| Subdomain enumeration | `subfinder` |
| Subdomain takeover detection | `subjack` + Python fingerprint check |

### Phase 2 — Active Reconnaissance
| Check | Tool/Method |
|---|---|
| Port scanning (web ports or full `-p-`) | `nmap` |
| HTTP methods enumeration | `nmap` NSE |
| WAF detection | `wafw00f` |
| CDN fingerprinting | Header analysis (Cloudflare, Akamai, Fastly, CloudFront, Azure, Sucuri) |
| Virtual host fuzzing | `ffuf` in vhost mode with baseline size filtering |

### Phase 3 — Technology & Content Discovery
| Check | Tool/Method |
|---|---|
| Technology fingerprinting | `whatweb`, `webanalyze` |
| `robots.txt` / `sitemap.xml` / `security.txt` | Native HTTP |
| General content discovery | `ffuf` with configurable wordlist |
| Admin panel discovery | `ffuf` with focused admin path wordlist |

### Phase 4 — HTTP Analysis
| Check | Method |
|---|---|
| Security header grading | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Version disclosure headers | `Server`, `X-Powered-By`, `X-AspNet-Version` |
| Cookie attribute auditing | `Secure`, `HttpOnly`, `SameSite` |
| HTTP Basic Auth detection | `WWW-Authenticate` header |
| HTTP/2 detection | `curl --http2` |
| Redirect chain analysis | Mixed-content hop detection |
| CORS misconfiguration | Origin reflection + `ACAC: true` combos |
| OAuth / OIDC endpoint enumeration | Well-known paths, Keycloak, IdentityServer |

### Phase 5 — Vulnerability Scanning
| Check | Tool/Method |
|---|---|
| SSL/TLS analysis | `testssl.sh` |
| Web vulnerability scanning | `nikto` |
| JavaScript secret extraction | 11 regex patterns (AWS keys, JWTs, GitHub tokens, hardcoded passwords, internal IPs, etc.) |
| GraphQL endpoint detection + introspection | Native HTTP |
| Path traversal probing | 6 payloads, Linux/Windows indicators |
| Open redirect probing | 10 common redirect parameters |
| XXE probing (OOB) | Configurable OOB callback URL (interactsh / Burp Collaborator) |
| Default credential testing | Tomcat, Jenkins, WordPress, Grafana |

### Phase 6 — Infrastructure
| Check | Method |
|---|---|
| S3 / GCS / Azure blob enumeration | Name permutation + public access probing |
| Screenshots | `gowitness` |

### Output
| File | Contents |
|---|---|
| `<prefix>.md` | Full markdown report with inline findings (severity, evidence, recommendation) |
| `<prefix>.findings.json` | Machine-readable structured findings for import into a findings DB |
| `<prefix>.state.json` | Scan state for `--resume` |

---

## Installation

### Clone
```bash
git clone https://github.com/Mr-Whiskerss/Web-Application-Enumeration-Script.git
cd Web-Application-Enumeration-Script
```

### Python dependencies
```bash
pip install requests colorama tqdm
```

### External tools

The script checks for tools at runtime and skips phases where the tool is missing. Install what you need:

```bash
# Kali / Debian
sudo apt install -y nmap nikto whatweb ffuf subfinder testssl.sh dnsrecon theharvester wafw00f curl gowitness

# Go tools
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/haccer/subjack@latest
go install github.com/rverton/webanalyze/cmd/webanalyze@latest
go install github.com/sensepost/gowitness@latest

# pip
pip install wafw00f theHarvester
```

SecLists is strongly recommended for content discovery and vhost fuzzing:
```bash
sudo apt install seclists
# or
git clone https://github.com/danielmiessler/SecLists /opt/SecLists
```

---

## Usage

### Basic
```bash
python3 web_app_pro.py -t example.com
```

### Route through Burp Suite
```bash
python3 web_app_pro.py -t example.com --proxy http://127.0.0.1:8080
```

### Non-interactive with OOB callback for XXE
```bash
python3 web_app_pro.py -t example.com --auto --oob-url abc123.interactsh.com
```

### Full port scan with custom rate limiting
```bash
python3 web_app_pro.py -t example.com --full-ports --rate 20 --delay 0.1
```

### With scope enforcement
```bash
python3 web_app_pro.py -t example.com --scope-file scope.txt
```

### With Google dork automation
```bash
python3 web_app_pro.py -t example.com --google-api-key YOUR_KEY --google-cx YOUR_CX
```

### Resume an interrupted scan
```bash
python3 web_app_pro.py -t example.com --resume
```

### Diff against a previous scan
```bash
python3 web_app_pro.py -t example.com --diff previous.findings.json
```

---

## All Flags

| Flag | Default | Description |
|---|---|---|
| `-t`, `--target` | — | Target domain or IP (required) |
| `-o`, `--output` | `webrecon` | Output file prefix |
| `--auto`, `-a` | off | Non-interactive mode — skips `y/n` prompts |
| `--proxy` | — | Proxy URL, e.g. `http://127.0.0.1:8080` |
| `--user-agent` | Chrome 120 UA | Custom User-Agent string |
| `--timeout` | `10` | HTTP request timeout in seconds |
| `--rate` | `50` | ffuf thread rate |
| `--delay` | `0.0` | Delay between ffuf requests in seconds |
| `--oob-url` | — | OOB callback host for XXE/SSRF probes |
| `--scope-file` | — | Scope file: CIDRs or domains, one per line |
| `--full-ports` | off | Run full `-p-` nmap scan instead of web port selection |
| `--google-api-key` | — | Google Custom Search API key |
| `--google-cx` | — | Google Custom Search Engine ID |
| `--diff` | — | Previous `.findings.json` to compare against |
| `--resume` | off | Resume from last completed phase |
| `--fresh` | off | Clear saved state and start from scratch |
| `--threads` | `5` | Number of parallel phase threads |
| `-v`, `--verbose` | off | Show tool stderr output in report |

---

## Scope File Format

```
# CIDRs and/or domains, one per line
# Lines starting with # are ignored

10.10.10.0/24
192.168.1.0/24
example.com
*.example.com
```

Targets not matching any entry are hard-blocked before any traffic is sent. Applies to the primary target and to any subdomains discovered during the scan.

---

## Output Structure

### Markdown report (`.md`)
Each finding is written inline with severity, phase, evidence block, and recommendation:

```markdown
### 🔴 [HIGH] Missing Header: strict-transport-security
**Phase:** header_analysis  |  **Time:** 2025-01-15T14:32:01

**Description:** Response does not include `strict-transport-security`.

**Evidence:**
```
Checked: https://example.com
```

**Recommendation:** Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### Findings JSON (`.findings.json`)
```json
[
  {
    "title": "Missing Header: strict-transport-security",
    "severity": "HIGH",
    "description": "Response does not include `strict-transport-security`.",
    "evidence": "Checked: https://example.com",
    "recommendation": "Add: Strict-Transport-Security: max-age=31536000; ...",
    "phase": "header_analysis",
    "timestamp": "2025-01-15T14:32:01"
  }
]
```

The findings JSON is structured to import directly into a pentest findings database or be consumed by a report generator.

---

## Diff Mode

Run two scans against the same target (e.g. before and after a remediation window) and compare:

```bash
# First scan
python3 web_app_pro.py -t example.com -o scan_jan

# Second scan, diffed against the first
python3 web_app_pro.py -t example.com -o scan_feb --diff scan_jan.findings.json
```

The final report section will list:
- **New** findings not present in the previous scan
- **Resolved** findings from the previous scan no longer present
- **Unchanged** finding count

---

## Resuming Scans

State is written to `<prefix>.state.json` after each phase completes. If a scan is interrupted (Ctrl+C, timeout, connection drop), re-run with the same output prefix and `--resume`:

```bash
python3 web_app_pro.py -t example.com -o myrecon --resume
```

Completed phases are skipped. Use `--fresh` to clear the state and restart from scratch.

---

## Notes

- **XXE probing** requires `--oob-url` pointing to an out-of-band callback host (interactsh, Burp Collaborator, etc.). Without it the phase is skipped cleanly.
- **Google dork automation** requires a Google Custom Search API key and engine ID. Without them, dork URLs are generated and logged for manual review.
- **`webanalyze`** is used in place of the deprecated `wappalyzer` CLI.
- Nmap OS detection (`-O`) will prompt for `sudo` if not running as root.
- Content discovery and Nikto prompt for confirmation in interactive mode. Use `--auto` to suppress all prompts.
- Screenshots are saved to `./screenshots/` relative to the working directory.

---

## Changelog

### v2.0
- Full rewrite in structured Python with dataclasses and typed interfaces
- Parallelised phase execution (`ThreadPoolExecutor`)
- Scope enforcement with CIDR and domain allowlists
- Resumable scan state
- Diff mode for before/after comparisons
- Proxy and custom User-Agent support throughout all native HTTP calls
- `shell=False` on all subprocess calls; input sanitisation
- HTTP scheme auto-detection with HTTPS-first fallback
- Structured `.findings.json` output with severity tags
- New: certificate transparency (crt.sh), Wayback Machine URL mining
- New: Google dork generation and optional API automation
- New: email harvesting (theHarvester)
- New: subdomain takeover fingerprint check (Python-native + subjack)
- New: WAF/CDN fingerprinting (wafw00f + header analysis)
- New: virtual host fuzzing (ffuf)
- New: security header grading (6 OWASP headers)
- New: cookie attribute auditing
- New: CORS misconfiguration detection
- New: OAuth/OIDC endpoint enumeration
- New: JavaScript secret extraction (11 patterns)
- New: GraphQL endpoint detection + introspection probe
- New: path traversal probing
- New: open redirect probing
- New: XXE probing with OOB callback support
- New: default credential testing (Tomcat, Jenkins, WordPress, Grafana)
- New: cloud storage bucket enumeration (S3, GCS, Azure)
- New: screenshots via gowitness
- New: ASN and IPv6 enumeration
- New: admin panel focused discovery wordlist
- Replaced deprecated `wappalyzer` CLI with `webanalyze`
- Expanded nmap port list to cover common non-standard web ports
- Diff mode output in final report summary

### v1.0
- Initial release — sequential scan phases wrapping nmap, nikto, whatweb, wappalyzer, subfinder, ffuf, testssl, dnsrecon, curl
