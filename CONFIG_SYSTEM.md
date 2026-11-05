# WebRecon Configuration System

## Overview

WebRecon now supports YAML-based configuration files for customizing scanning behavior without editing code. Configuration follows a clear priority hierarchy, allowing multiple levels of customization.

## Installation

Configuration requires PyYAML:
```bash
pip install PyYAML
```

Without PyYAML, the tool still works using CLI arguments and hardcoded defaults, but config files are not supported.

## Configuration Priority

Configuration values are loaded in this order (highest priority last):

1. **Hardcoded defaults** (in code) - Lowest priority
2. **`~/.webrecon-config.yaml`** - User global config
3. **`./webrecon-config.yaml`** - Project-level config (current directory)
4. **`-C/--config`** - Explicit config file flag
5. **CLI arguments** - Highest priority (always override config)

### Example

```bash
# 1. Uses defaults + ~/.webrecon-config.yaml (if exists)
python3 web_app.py -t example.com

# 2. Uses defaults + ~/.webrecon-config.yaml + ./webrecon-config.yaml (if exists)
python3 web_app.py -t example.com

# 3. Uses defaults + explicit config file
python3 web_app.py -t example.com -C configs/config.aggressive.yaml

# 4. Explicit config + override with CLI arg (threads=10 overrides config)
python3 web_app.py -t example.com -C config.yaml --threads 10
```

## Quick Start

### 1. View Available Configs

```bash
ls -la configs/
# config.example.yaml    - Fully commented template
# config.aggressive.yaml - Fast, all checks enabled
# config.stealth.yaml    - Slow, quiet, intrusive checks disabled
# config.minimal.yaml    - Bare essentials
```

### 2. Set Up User Global Config

```bash
# Copy example to home directory
cp configs/config.example.yaml ~/.webrecon-config.yaml

# Edit with your defaults
nano ~/.webrecon-config.yaml
```

### 3. Use a Pre-built Profile

```bash
# Aggressive scanning (fast, thorough)
python3 web_app.py -t example.com -C configs/config.aggressive.yaml

# Stealth mode (slow, quiet)
python3 web_app.py -t example.com -C configs/config.stealth.yaml

# Minimal (quick reconnaissance)
python3 web_app.py -t example.com -C configs/config.minimal.yaml
```

### 4. Display Effective Configuration

```bash
# Show all active config values (after loading from files + args)
python3 web_app.py -t example.com --show-config

# Show with explicit config
python3 web_app.py -t example.com -C configs/config.aggressive.yaml --show-config
```

## Configuration Sections

### `scanning`

Core scanning parameters:

```yaml
scanning:
  threads: 5              # Parallel execution threads
  timeout: 10            # HTTP request timeout (seconds)
  rate: 50               # Requests per second for fuzzing tools
  delay: 0.0             # Delay between requests (seconds)
  full_ports: false      # Run nmap full port scan (-p-)?
  verbose: false         # Verbose output (also controlled by -v)

  wordlists:
    common: /path/to/common.txt
    subdomains: /path/to/subdomains.txt

  ports:
    web: "80,443,8080,8443,..."  # nmap port list

  api_endpoints:
    common:
      - /api/
      - /graphql/

  paths:
    vcs: ["/.git/", "/.svn/"]
    config: ["/.env", "/.htpasswd"]
```

### `credentials`

Default credentials for testing:

```yaml
credentials:
  wordpress:
    - user: admin
      password: admin
  tomcat:
    - user: tomcat
      password: tomcat
  jenkins:
    - user: admin
      password: admin
```

### `tools`

Tool-specific configuration:

```yaml
tools:
  # Timeouts for different tools
  nmap_timeout: 600
  whatweb_timeout: 120
  arjun_timeout: 1200

  # Custom tool paths (if not in standard PATH)
  tool_paths:
    nmap: /usr/bin/nmap
    nuclei: null  # Use PATH

  # Custom nuclei templates
  nuclei_templates: ${HOME}/.config/nuclei/templates
```

### `reporting`

Output and report configuration:

```yaml
reporting:
  format: html           # html, json, markdown
  html_theme: dark       # dark or light
  max_evidence_length: 1500

  # Which formats to generate
  html_report: true
  json_report: true
  markdown_report: true

  # Which severities to include
  include_findings_by_severity:
    - CRITICAL
    - HIGH
    - MEDIUM
```

### `integrations`

External service integration:

```yaml
integrations:
  # Discord/Slack webhook
  webhook_url: https://hooks.slack.com/services/YOUR/WEBHOOK
  webhook_threshold: HIGH  # Only send HIGH+ findings

  # PentestDB storage
  pentestdb_url: http://localhost:5000
  pentestdb_token: your-api-token
```

### `profiles`

Predefined scan profiles:

```yaml
profiles:
  recon:
    description: "Passive only"
    threads: 5
    no_intrusive: true

  aggressive:
    description: "Fast and thorough"
    threads: 10
    rate: 100
    no_intrusive: false
```

Use with: `python3 web_app.py -t example.com --profile aggressive`

## Environment Variables

Configuration supports environment variable expansion using `${VAR}` syntax:

```yaml
wordlists:
  custom: ${HOME}/.webrecon/wordlists/custom.txt
  seclists: ${SECLISTS_PATH}/Discovery/Web-Content/common.txt

tools:
  nuclei_templates: ${HOME}/.config/nuclei/templates
```

Supported variables: `${HOME}`, `${USER}`, `${PWD}`, `${PATH}`, etc.

## Creating Custom Configs

### 1. Copy the Example

```bash
cp configs/config.example.yaml my-config.yaml
```

### 2. Edit for Your Needs

```yaml
# my-config.yaml
scanning:
  threads: 8              # More threads for parallel scanning
  rate: 100              # Higher rate for faster fuzzing
  full_ports: false      # Don't do full port scan by default

tools:
  # Custom tool paths for your environment
  tool_paths:
    nmap: /usr/local/bin/nmap
    nuclei: /home/user/go/bin/nuclei
```

### 3. Use It

```bash
# Option A: Use as explicit config
python3 web_app.py -t example.com -C my-config.yaml

# Option B: Copy to project directory
cp my-config.yaml ./webrecon-config.yaml
python3 web_app.py -t example.com

# Option C: Copy to home directory
cp my-config.yaml ~/.webrecon-config.yaml
python3 web_app.py -t example.com
```

## Profiles Explained

### Recon
- **Use case:** Passive reconnaissance only
- **Speed:** Fast
- **Intrusiveness:** None
- **Features:** DNS, certificates, WHOIS, email harvesting
- **Command:** `python3 web_app.py -t example.com --profile recon`

### Active
- **Use case:** Passive + active probing
- **Speed:** Medium
- **Intrusiveness:** Low
- **Features:** Port scanning, WAF detection, tech fingerprinting
- **Command:** `python3 web_app.py -t example.com --profile active`

### Full
- **Use case:** Complete vulnerability scan
- **Speed:** Slow
- **Intrusiveness:** High
- **Features:** All checks enabled
- **Command:** `python3 web_app.py -t example.com --profile full`

### Stealth
- **Use case:** Avoid detection/rate limits
- **Speed:** Very slow
- **Intrusiveness:** Low
- **Features:** Full checks but throttled
- **Command:** `python3 web_app.py -t example.com --profile stealth`

### Aggressive
- **Use case:** Maximum coverage in minimum time
- **Speed:** Very fast
- **Intrusiveness:** Very high
- **Features:** All intrusive checks enabled
- **Command:** `python3 web_app.py -t example.com -C configs/config.aggressive.yaml`

## Validation

The system validates configuration at startup:

```bash
✓ Valid scanning.threads: 5
✓ Valid scanning.timeout: 10
⚠ Wordlist not found: /missing/path/common.txt
```

Warnings are logged but don't prevent scanning. Errors are reported clearly.

## Troubleshooting

### Config File Not Found

```
Config file not found: /path/to/config.yaml
```

**Solution:** Check the file path and permissions

### Invalid YAML

```
YAML parse error in config.yaml: mapping values are not allowed here
```

**Solution:** YAML syntax error. Use a YAML validator or check indentation.

### Missing PyYAML

```
⚠ Config file support requires PyYAML. Install with: pip install PyYAML
```

**Solution:** Install PyYAML, or use CLI arguments without config files

### Values Not Being Applied

**Debugging:**

```bash
# Show effective configuration
python3 web_app.py --show-config

# Show with verbose logging
python3 web_app.py -t example.com -C config.yaml -v 2>&1 | grep -i config
```

### CLI Args Not Overriding Config

Remember: **CLI args have HIGHEST priority**

```bash
# Config says threads: 5, but CLI overrides it
python3 web_app.py -t example.com -C config.yaml --threads 10
# Result: threads = 10
```

## Best Practices

1. **Start with a template:** Copy `config.example.yaml` as your base
2. **Use projects:** Create `webrecon-config.yaml` in each project directory
3. **Version control:** Commit config files to git (except secrets)
4. **Secrets:** Don't store API keys in config. Use environment variables or CLI args
5. **Profiles:** Create different configs for different scan types (aggressive, stealth, etc.)
6. **Documentation:** Add comments to custom configs explaining your choices

## Examples

### Team Configuration

```bash
# Setup team-wide defaults
cp configs/config.example.yaml .webrecon-config.yaml
git add .webrecon-config.yaml
git commit -m "Add standard WebRecon configuration"

# Team members pull and use automatically
python3 web_app.py -t example.com  # Uses team defaults
```

### Project-Specific Config

```bash
# Create per-project config
cat > webrecon-config.yaml <<'EOF'
scanning:
  threads: 8
  timeout: 15
  
tools:
  nuclei_templates: ./nuclei-templates/custom
  
reporting:
  include_findings_by_severity: [CRITICAL, HIGH, MEDIUM]
EOF

# Scan uses project defaults
python3 web_app.py -t example.com
```

### Engagement Config

```bash
# Create config for specific engagement
cp configs/config.aggressive.yaml engagement-2024-01.yaml

# Customize for this engagement
nano engagement-2024-01.yaml  # Adjust rate, threads, etc.

# Run all targets with engagement config
python3 web_app.py -iL targets.txt -C engagement-2024-01.yaml --auto
```

## Config File Location Reference

| Location | Priority | Use Case |
|----------|----------|----------|
| CLI argument `-C config.yaml` | 1 (Highest) | Explicit config for this run |
| `./webrecon-config.yaml` | 2 | Project-level defaults |
| `~/.webrecon-config.yaml` | 3 | User global defaults |
| CLI arguments | 1 (Highest) | Override any config |
| Hardcoded defaults | 4 (Lowest) | Fallback if no config |

Note: CLI arguments always have highest priority. Config merges with defaults, not replaces.
