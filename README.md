# 🕸️ Web Application Enumeration Script

A Python-based reconnaissance tool that automates the initial stages of web application enumeration, helping pentesters save time during engagements.

## 📖 Overview

Originally developed as a basic Bash script, this project has evolved into a powerful and flexible Python tool. It automates essential tasks for quickly assessing web infrastructure security during manual pentesting.

**Note:** This tool generates considerable traffic and is not recommended for stealthy Red Team operations.

## 🛠️ Features

- **Automatic Tool Detection** - Checks for required tools at startup and offers to install missing ones
- **Multi-Package Manager Support** - Detects and uses apt, dnf, yum, pacman, brew, go, npm, pip, and gem
- **Automatic Privilege Escalation** - Detects when sudo is needed and prompts accordingly
- **Subdomain Enumeration** - Discovers subdomains using Subfinder
- **Technology Fingerprinting** - Dual detection with WhatWeb and Wappalyzer
- **Content Discovery** - Directory/file fuzzing with ffuf
- **Comprehensive SSL/TLS Analysis** - Deep inspection using testssl.sh
- **DNS Reconnaissance** - NSLookup and DNSRecon integration
- **Vulnerability Scanning** - Nikto web vulnerability scanner
- **HTTP Methods Detection** - Identifies allowed HTTP methods
- **Robots.txt & Sitemap Discovery** - Extracts hidden paths and endpoints
- **Markdown Report Output** - Clean, readable output format
- **Progress Tracking** - Visual progress bar for scan status

## 📦 Required Tools

The script will check for these tools and offer to install any that are missing:

| Tool | Description | Primary Install |
|------|-------------|-----------------|
| `nslookup` | DNS lookup utility | `apt install dnsutils` |
| `dnsrecon` | DNS enumeration | `apt install dnsrecon` |
| `nmap` | Network scanner | `apt install nmap` |
| `whatweb` | Web technology identifier | `apt install whatweb` |
| `wappalyzer` | Technology profiler | `npm install -g wappalyzer` |
| `curl` | URL transfer tool | `apt install curl` |
| `nikto` | Web vulnerability scanner | `apt install nikto` |
| `testssl.sh` | SSL/TLS testing | `apt install testssl.sh` |
| `ffuf` | Fast web fuzzer | `apt install ffuf` |
| `subfinder` | Subdomain discovery | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |

### Python Dependencies

```bash
pip install colorama tqdm
```

### Wordlists (for ffuf)

The script auto-detects wordlists from common locations:
- `/usr/share/wordlists/dirb/common.txt`
- `/usr/share/seclists/Discovery/Web-Content/common.txt`
- `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`
- `/opt/SecLists/Discovery/Web-Content/common.txt`

Install SecLists for best results:
```bash
sudo apt install seclists
```

## 🔐 Privileges & Sudo

Some scans require root privileges to function properly:

| Scan | Requires Root | Reason |
|------|---------------|--------|
| Nmap OS Detection (`-O`) | ✅ Yes | Raw socket access |
| Nmap Service Scan (`-sV`) | ⚠️ Recommended | Better accuracy |
| HTTP Methods Check | ⚠️ Recommended | NSE script access |
| Other scans | ❌ No | Run as normal user |

**The script handles this automatically:**
- Detects if running as root
- If not root, automatically prepends `sudo` to commands that need it
- Displays a warning at startup if not running as root

```
⚠ Not running as root. Some scans (nmap -O) will use sudo.
  You may be prompted for your password.
```

**Running options:**
```bash
# Option 1: Run as normal user (will prompt for sudo when needed)
python3 web_app.py --target example.com

# Option 2: Run entire script as root (no sudo prompts)
sudo python3 web_app.py --target example.com
```

## 🚀 Getting Started

### Installation

1. Clone the repository:
```bash
git clone https://github.com/Mr-Whiskerss/web-app-enum.git
cd web-app-enum
```

2. Install Python dependencies:
```bash
pip install colorama tqdm
```

3. Make the script executable:
```bash
chmod +x web_app.py
```

### Usage

**Interactive mode:**
```bash
python3 web_app.py
```

**With target specified:**
```bash
python3 web_app.py --target example.com
```

**Custom output file:**
```bash
python3 web_app.py --target example.com -o report.md
```

**Skip tool dependency check:**
```bash
python3 web_app.py --target example.com --skip-check
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `--target` | Target domain or IP address |
| `-o, --output` | Output file name (default: `web_recon_output.md`) |
| `--skip-check` | Skip tool dependency check |
| `--auto` | Run without prompts (planned) |

## 📋 Scan Phases

The script runs through these phases:

| Phase | Description | Tools Used |
|-------|-------------|------------|
| 1. Passive Recon | DNS lookups and enumeration | nslookup, dnsrecon |
| 2. Subdomain Enumeration | Discover subdomains (domains only) | subfinder |
| 3. Active Recon | Port scanning and service detection | nmap |
| 4. HTTP Methods | Identify allowed HTTP methods | nmap NSE |
| 5. Technology Detection | Fingerprint web technologies | whatweb, wappalyzer |
| 6. Robots/Sitemap | Extract paths from config files | curl |
| 7. Content Discovery | Directory and file fuzzing | ffuf |
| 8. Vulnerability Scan | Web vulnerability detection | nikto |
| 9. SSL/TLS Analysis | Certificate and cipher analysis | testssl.sh |

## 📄 Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║                  Web Reconnaissance Tool                     ║
║                                                              ║
║  Tools: nmap, nikto, whatweb, wappalyzer, subfinder,        ║
║         ffuf, testssl.sh, dnsrecon, curl                    ║
╚══════════════════════════════════════════════════════════════╝

⚠ Not running as root. Some scans (nmap -O) will use sudo.
  You may be prompted for your password.

==================================================
Checking Required Tools
==================================================

[✓] nslookup - DNS lookup utility
[✓] dnsrecon - DNS enumeration tool
[✓] nmap - Network scanner
[✓] whatweb - Web technology identifier
[✓] curl - URL transfer tool
[✓] nikto - Web vulnerability scanner
[✓] testssl - SSL/TLS testing tool
[✓] ffuf - Fast web fuzzer for content discovery
[✓] subfinder - Subdomain discovery tool
[✓] wappalyzer - Technology profiler for websites

All required tools are installed!

Enter URL or IP address to be tested: example.com

Target: example.com (domain)
Output: web_recon_output.md

Overall Progress: 100%|████████████████████████| 13/13
```

## 📊 Output Report

The script generates a Markdown report (`web_recon_output.md`) containing:

- Target information
- DNS lookup results
- Discovered subdomains
- Open ports and services
- Detected technologies
- robots.txt and sitemap.xml contents
- Discovered directories/files
- Vulnerability findings
- SSL/TLS configuration details

## 🔥 Upcoming Features

- [ ] Nuclei vulnerability scanning integration
- [ ] httpx HTTP probing
- [ ] JavaScript library enumeration
- [ ] Virtual hosting discovery
- [ ] Multi-host scanning support
- [ ] HTML report generation
- [ ] API endpoint discovery
- [ ] Screenshot capture with gowitness
- [ ] Automated mode (`--auto` flag)

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-tool`)
3. Commit your changes (`git commit -m 'Add new tool integration'`)
4. Push to the branch (`git push origin feature/new-tool`)
5. Open a Pull Request

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any systems you do not own. Unauthorized access to computer systems is illegal.

## 📜 License

This project is licensed under the GNU GPL-3.0 License.
