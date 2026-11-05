# WebRecon Config System - Quick Reference

## TL;DR

```bash
# Install YAML support (optional but recommended)
pip install PyYAML

# Show all available options
python3 web_app.py --show-config

# Scan with aggressive profile (fast)
python3 web_app.py -t example.com -C configs/config.aggressive.yaml

# Scan with stealth profile (slow, quiet)
python3 web_app.py -t example.com -C configs/config.stealth.yaml

# Create custom config
cp configs/config.example.yaml my-config.yaml
nano my-config.yaml
python3 web_app.py -t example.com -C my-config.yaml

# Set global defaults
cp configs/config.example.yaml ~/.webrecon-config.yaml
nano ~/.webrecon-config.yaml
# Now all scans use these defaults automatically
```

## One-Minute Setup

1. **Install YAML support:**
   ```bash
   pip install PyYAML
   ```

2. **Copy example config to home:**
   ```bash
   cp configs/config.example.yaml ~/.webrecon-config.yaml
   ```

3. **Edit your defaults:**
   ```bash
   nano ~/.webrecon-config.yaml
   ```

4. **Use automatically:**
   ```bash
   python3 web_app.py -t example.com
   # Now uses your ~/.webrecon-config.yaml
   ```

## Common Tasks

### Use Built-in Profile

```bash
# Fast, thorough scanning
python3 web_app.py -t example.com -C configs/config.aggressive.yaml

# Slow, quiet scanning
python3 web_app.py -t example.com -C configs/config.stealth.yaml

# Bare essentials only
python3 web_app.py -t example.com -C configs/config.minimal.yaml
```

### Create Team Config

```bash
# In your project directory
cp configs/config.example.yaml webrecon-config.yaml
nano webrecon-config.yaml
git add webrecon-config.yaml
git commit -m "Add WebRecon config"

# Team members run:
python3 web_app.py -t example.com  # Uses team defaults
```

### Override Config with CLI

```bash
# Config says threads: 5, but you want more
python3 web_app.py -t example.com -C config.yaml --threads 20

# Multiple overrides
python3 web_app.py -t example.com -C config.yaml --threads 20 --timeout 15 --rate 100
```

### Debug Configuration

```bash
# Show what values will be used
python3 web_app.py --show-config

# Show with verbose logging
python3 web_app.py --show-config -v

# Show with specific config file
python3 web_app.py --show-config -C my-config.yaml
```

## Config Files Location

| Where | Priority | When Used |
|-------|----------|-----------|
| `-C config.yaml` | 1st | Explicit flag (highest) |
| `./webrecon-config.yaml` | 2nd | Project-level defaults |
| `~/.webrecon-config.yaml` | 3rd | User-level defaults |
| Hardcoded | 4th | Fallback (lowest) |

**CLI arguments override everything!**

## Config Keys (Most Common)

```yaml
# How many threads to use
scanning:
  threads: 5

# HTTP timeout in seconds
scanning:
  timeout: 10

# Requests per second for fuzzing
scanning:
  rate: 50

# Add delay between requests (seconds)
scanning:
  delay: 0.5

# Run full port scan instead of common ports?
scanning:
  full_ports: false

# Your preferred output format
reporting:
  format: html  # or json, markdown

# Send findings to Slack/Discord
integrations:
  webhook_url: https://hooks.slack.com/services/YOUR/WEBHOOK
```

## Profiles Explained

| Profile | Speed | Loud | Intrusive | Use Case |
|---------|-------|------|-----------|----------|
| recon | Fast | Yes | No | Passive reconnaissance |
| active | Medium | Yes | No | Active probing |
| full | Slow | Yes | Yes | Complete scan |
| stealth | Very slow | No | No | Avoid detection |
| aggressive | Very fast | Yes | Yes | Maximum coverage |

```bash
python3 web_app.py -t example.com --profile recon
python3 web_app.py -t example.com --profile aggressive
```

## Environment Variables in Config

```yaml
# These work:
wordlists:
  common: ${HOME}/.webrecon/wordlists/common.txt
  seclists: ${SECLISTS_PATH}/Discovery/Web-Content/

tools:
  nuclei_templates: ${HOME}/.config/nuclei/templates
```

Available: `${HOME}`, `${USER}`, `${PWD}`, `${PATH}`, any env var

## Troubleshooting

### "PyYAML not installed"
```bash
pip install PyYAML
```

### "Config file not found"
```bash
# Check path exists
ls -la your-config.yaml

# Try absolute path
python3 web_app.py -t example.com -C /full/path/to/config.yaml
```

### "Values not being used"
```bash
# Debug what config is loaded
python3 web_app.py --show-config -C your-config.yaml

# Remember: CLI args override config
python3 web_app.py -t example.com -C config.yaml --threads 10
# threads = 10 (CLI wins)
```

### "Wordlist not found"
```bash
# Check path
ls -la /path/to/wordlist.txt

# Use absolute path in config
wordlists:
  common: /usr/share/seclists/Discovery/Web-Content/common.txt
```

## Example Configs

### Fast Team Scan
```yaml
scanning:
  threads: 8
  rate: 100
  
reporting:
  format: html
  include_findings_by_severity: [CRITICAL, HIGH]
```

### Careful Engagement
```yaml
scanning:
  threads: 3
  rate: 20
  delay: 1.0
  
reporting:
  format: html
  include_findings_by_severity: [CRITICAL, HIGH, MEDIUM]
```

### Reconnaissance Only
```yaml
scanning:
  threads: 5
  
# Other settings use defaults
# Result: passive-only scanning
```

## Command Reference

```bash
# Show effective config
python3 web_app.py --show-config

# Use specific config
python3 web_app.py -t example.com -C configs/config.aggressive.yaml

# Override config value
python3 web_app.py -t example.com -C config.yaml --threads 20

# Use project config automatically
cd my-project
python3 web_app.py -t example.com  # Uses ./webrecon-config.yaml

# Scan multiple targets with config
python3 web_app.py -iL targets.txt -C configs/config.stealth.yaml --auto

# Batch scan with project config
cd my-project
python3 web_app.py -iL targets.txt --auto
# Uses ./webrecon-config.yaml + ~/.webrecon-config.yaml
```

## Files Reference

| File | Purpose |
|------|---------|
| `config.py` | Config management code |
| `configs/config.example.yaml` | Documented template |
| `configs/config.aggressive.yaml` | Fast profile |
| `configs/config.stealth.yaml` | Quiet profile |
| `configs/config.minimal.yaml` | Bare essentials |
| `CONFIG_SYSTEM.md` | Full documentation |
| `IMPLEMENTATION_SUMMARY.md` | Technical details |

## Tips & Tricks

### Tip 1: Project Defaults
```bash
# Create project-specific config
cd my-engagement
cp ../configs/config.example.yaml webrecon-config.yaml
nano webrecon-config.yaml
# All scans in this directory use these defaults
```

### Tip 2: Multiple Profiles
```bash
cp configs/config.aggressive.yaml aggressive.yaml
cp configs/config.stealth.yaml stealth.yaml
cp configs/config.minimal.yaml minimal.yaml

python3 web_app.py -t target1.com -C aggressive.yaml
python3 web_app.py -t target2.com -C stealth.yaml
```

### Tip 3: Combine Config + CLI
```bash
# Config has conservative defaults
python3 web_app.py -t example.com -C config.yaml --threads 20 --rate 100
# Now running with modified parameters
```

### Tip 4: Generate Reports You Want
```yaml
reporting:
  html_report: true
  json_report: true
  markdown_report: false  # Skip markdown if you don't need it
```

### Tip 5: Use Environment Variables
```bash
# In your shell:
export SECLISTS_PATH=/path/to/seclists

# In config.yaml:
wordlists:
  subdomains: ${SECLISTS_PATH}/Discovery/DNS/subdomains.txt

python3 web_app.py -t example.com -C config.yaml
# Works with your SECLISTS_PATH
```

## See Also

- `CONFIG_SYSTEM.md` - Full documentation
- `IMPLEMENTATION_SUMMARY.md` - Technical details
- `configs/config.example.yaml` - All available options
