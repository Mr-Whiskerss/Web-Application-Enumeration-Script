# WebRecon Configuration System - Implementation Summary

## What Was Built

### 1. **config.py Module** (New)
A complete configuration management system with:

- **ConfigManager Class**: Loads, merges, and manages configuration
- **Default Configuration**: Comprehensive defaults for all settings
- **Environment Variable Expansion**: Supports `${HOME}`, `${USER}`, `${PWD}`, etc.
- **Config Merging**: Priority-based loading from multiple sources
- **Validation**: Checks for issues and logs warnings
- **Dot Notation Access**: `cfg.get("scanning.threads")` for nested values

**Key Functions:**
- `load_config_file()` - Load YAML config with error handling
- `merge_configs()` - Recursive dict merging with precedence
- `validate_config()` - Check configuration validity
- `print_config()` - Pretty-print config for debugging
- `expand_env_vars()` - Expand environment variables recursively

### 2. **Configuration Files** (New)

**configs/config.example.yaml**
- Fully commented template showing all available options
- Serves as documentation and starting point for custom configs

**configs/config.aggressive.yaml**
- Scan profile: Fast (10 threads, rate 100, no delays)
- All checks enabled (intrusive enabled)
- Use case: Maximum coverage in minimum time

**configs/config.stealth.yaml**
- Scan profile: Slow (2 threads, rate 10, 1s delays)
- Intrusive checks disabled
- Use case: Avoid detection, respect rate limits

**configs/config.minimal.yaml**
- Scan profile: Bare essentials
- Only HIGH/CRITICAL findings
- JSON + Markdown output only
- Use case: Quick reconnaissance

### 3. **Main Script Updates** (web_app.py)

**Imports:**
- Import ConfigManager and config utilities
- Check for PyYAML (graceful degradation if missing)

**Argument Parser:**
- Add `-C/--config` flag for explicit config file
- Add `--show-config` flag to display effective configuration

**Main Function:**
- Initialize ConfigManager after logging setup
- Load config from multiple sources with priority
- Support `--show-config` to display and exit
- Pass cfg_mgr to run_single_target()

**Config Integration:**
- Create `get_cfg()` helper for value precedence
- Values: CLI args > config file > defaults
- Support both old CLI-only mode and new config mode

**run_single_target() Updates:**
- Accept optional cfg_mgr parameter
- Use config values for scanning parameters
- CLI args always override config values

### 4. **Documentation** (New)

**CONFIG_SYSTEM.md**
- Quick start guide
- Configuration priority explanation
- Detailed section reference
- Environment variable usage
- Troubleshooting guide
- Best practices
- Usage examples
- Config location reference

## Configuration Structure

```yaml
scanning:
  threads: 5
  timeout: 10
  rate: 50
  wordlists: {...}
  ports: {...}
  api_endpoints: {...}
  paths: {...}

credentials:
  wordpress: [...]
  tomcat: [...]

tools:
  nmap_timeout: 600
  tool_paths: {...}

reporting:
  format: html
  html_theme: dark

integrations:
  webhook_url: null
  pentestdb_url: null

profiles:
  recon: {...}
  aggressive: {...}
  stealth: {...}
```

## Priority Hierarchy (How Values Are Loaded)

```
Lowest Priority:
  1. Hardcoded defaults in code
  2. ~/.webrecon-config.yaml (user global)
  3. ./webrecon-config.yaml (project-level)
  4. -C/--config flag (explicit file)
Highest Priority:
  5. CLI arguments (always win)
```

Example:
```bash
# Scenario: config says threads=5, CLI says --threads 10
python3 web_app.py -t example.com -C config.yaml --threads 10
# Result: threads = 10 (CLI wins)
```

## Usage Examples

### Basic Usage
```bash
# Use default config (searches ~/.webrecon-config.yaml, ./webrecon-config.yaml)
python3 web_app.py -t example.com
```

### With Explicit Config
```bash
# Use aggressive profile
python3 web_app.py -t example.com -C configs/config.aggressive.yaml

# Use stealth profile
python3 web_app.py -t example.com -C configs/config.stealth.yaml
```

### Display Configuration
```bash
# Show effective configuration before scanning
python3 web_app.py -t example.com --show-config

# Show with verbose logging
python3 web_app.py -t example.com --show-config -v
```

### Override Config with CLI
```bash
# Config has threads: 5, but override to 20
python3 web_app.py -t example.com -C config.yaml --threads 20

# Multiple overrides
python3 web_app.py -t example.com -C config.yaml --threads 20 --timeout 15 --rate 100
```

### Batch Scanning with Config
```bash
# Scan multiple targets using config
python3 web_app.py -iL targets.txt -C configs/config.aggressive.yaml --auto
```

## Key Features

### ✅ Priority-Based Merging
- CLI arguments always have highest priority
- Config files can be layered
- Defaults only used if nothing else specified

### ✅ Environment Variable Support
```yaml
wordlists:
  custom: ${HOME}/.webrecon/wordlists/
tools:
  nuclei_templates: ${SECLISTS_PATH}/templates
```

### ✅ Validation
- Checks for missing wordlists
- Validates numeric values (threads, timeout)
- Logs warnings without crashing

### ✅ Auto-Discovery
- Automatically loads `~/.webrecon-config.yaml` if exists
- Automatically loads `./webrecon-config.yaml` if exists
- Can be overridden with `-C` flag

### ✅ Graceful Degradation
- Works fine without PyYAML installed (uses defaults + CLI args)
- Config files optional (not required to run)
- Clear warnings if PyYAML missing

### ✅ Backwards Compatible
- All existing CLI arguments still work
- No breaking changes to existing workflows
- Optional feature (can ignore if you want)

## File Changes

### New Files
```
config.py                          - Config management module
configs/config.example.yaml        - Template with all options
configs/config.aggressive.yaml     - Aggressive profile
configs/config.stealth.yaml        - Stealth profile
configs/config.minimal.yaml        - Minimal profile
CONFIG_SYSTEM.md                   - Config documentation
IMPLEMENTATION_SUMMARY.md          - This file
```

### Modified Files
```
web_app.py                         - Added config integration
                                   - New CLI flags
                                   - Config loading in main()
```

## Testing the Implementation

### Test 1: Show Default Config
```bash
python3 web_app.py --show-config
# Should display all default values in YAML format
```

### Test 2: Use Aggressive Profile
```bash
python3 web_app.py -t example.com -C configs/config.aggressive.yaml --show-config
# Should show aggressive values (threads: 10, rate: 100, etc.)
```

### Test 3: Override Config with CLI
```bash
python3 web_app.py -t example.com -C configs/config.stealth.yaml --threads 20 --show-config
# Should show threads: 20 (CLI overrides config.stealth.yaml)
```

### Test 4: Environment Variables
```bash
# Create config with env var
echo 'scanning:
  threads: 5' > test-config.yaml

python3 web_app.py --show-config -C test-config.yaml
# Should display the config correctly
```

### Test 5: Without PyYAML
```bash
# If PyYAML not installed, should still work
python3 web_app.py -t example.com
# Should run with defaults + CLI args (no error about missing YAML)
```

## Future Enhancements

Ideas for extending the config system:

1. **Config Inheritance**: Have configs extend other configs
   ```yaml
   extends: configs/config.aggressive.yaml
   scanning:
     threads: 20  # Override just this value
   ```

2. **Config Validation Schema**: YAML schema to validate structure

3. **Config Templates**: Generate configs from templates with prompts

4. **Per-Target Overrides**: Different settings per target in batch mode

5. **Config Versioning**: Track config changes over time

6. **Interactive Config Builder**: CLI wizard to create configs

## Backwards Compatibility

✅ **Fully backwards compatible:**
- Existing CLI arguments unchanged
- All commands work the same with or without config
- Config is optional (not required)
- No changes to output formats or behavior
- Users can ignore config system entirely if they want

## Dependencies

**Optional:**
- PyYAML (for config file support)
  - Install: `pip install PyYAML`
  - Tool works fine without it (just no config files)

**No new required dependencies added**

## Summary

The config system provides:

- 🎯 **Flexibility**: Multiple ways to configure scanning
- 🤝 **Collaboration**: Share configs via git
- ⚙️ **Customization**: Without editing code
- 📋 **Profiles**: Pre-built scanning modes
- 🔄 **Compatibility**: Works with existing workflows
- 📊 **Precedence**: Clear priority for config values
- 🛡️ **Safety**: Validation and error handling

All while maintaining 100% backwards compatibility!
