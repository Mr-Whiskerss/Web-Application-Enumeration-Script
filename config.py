"""
WebRecon Configuration Management

Handles loading, merging, and validating configuration from:
1. Hardcoded defaults (lowest priority)
2. ~/.webrecon-config.yaml (user global)
3. ./webrecon-config.yaml (project-level)
4. -C/--config flag (explicit file)
5. CLI arguments (highest priority - overrides all)
"""

import os
import sys
import logging
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger("webrecon")

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logger.warning("PyYAML not installed. Config file support disabled. Install with: pip install PyYAML")


# ═════════════════════════════════════════════════════════════════════════════
# DEFAULT CONFIGURATION
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_CONFIG = {
    "scanning": {
        "threads": 5,
        "timeout": 10,
        "rate": 50,
        "delay": 0.0,
        "full_ports": False,
        "verbose": False,

        "wordlists": {
            "common": "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "subdomains": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "admin": None,  # Generated on-the-fly if not specified
        },

        "ports": {
            "web": "21,22,23,25,53,80,81,88,110,143,389,443,445,465,587,636,993,995,"
                   "1080,1443,2049,3000,3306,3389,4443,4848,5000,5432,5900,6379,7001,"
                   "7443,8000,8080,8081,8443,8444,8888,9000,9090,9200,9443,10000,27017",
        },

        "api_endpoints": {
            "common": [
                "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
                "/v1/", "/v2/", "/v3/",
                "/rest/", "/graphql/", "/rpc/",
            ]
        },

        "paths": {
            "vcs": ["/.git/", "/.svn/", "/.hg/", "/.bzr/"],
            "config": ["/.env", "/.env.local", "/.htpasswd", "/.aws/", "/.ssh/"],
            "backup": ["/index.php~", "/index.php.bak", "/index.php.old", "/web.config.bak"],
            "admin": [
                "admin", "administrator", "admin.php", "admin/login",
                "wp-admin", "wp-login.php", "cpanel", "plesk", "phpmyadmin",
            ],
        },
    },

    "credentials": {
        "wordpress": [
            {"user": "admin", "password": "admin"},
            {"user": "admin", "password": "password"},
        ],
        "drupal": [
            {"user": "admin", "password": "admin"},
        ],
        "tomcat": [
            {"user": "tomcat", "password": "tomcat"},
            {"user": "tomcat", "password": "s3cret"},
            {"user": "admin", "password": "admin"},
        ],
        "jenkins": [
            {"user": "admin", "password": "admin"},
        ],
        "generic": [
            {"user": "admin", "password": "admin"},
            {"user": "admin", "password": "password"},
            {"user": "root", "password": "root"},
        ],
    },

    "tools": {
        "nmap_timeout": 600,
        "nmap_full_timeout": 2400,
        "whatweb_timeout": 120,
        "arjun_timeout": 1200,
        "nuclei_timeout": 1800,
        "nikto_timeout": 900,

        # Custom tool paths (leave empty to use PATH)
        "tool_paths": {
            "nmap": None,
            "nuclei": None,
            "katana": None,
            "ffuf": None,
            "wpscan": None,
        },

        # Custom nuclei templates
        "nuclei_templates": None,  # Uses default or ~/.config/nuclei/templates
    },

    "reporting": {
        "format": "html",  # html, json, markdown
        "include_findings_by_severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        "html_theme": "dark",  # dark or light
        "max_evidence_length": 1500,
        "html_report": True,
        "json_report": True,
        "markdown_report": True,
    },

    "integrations": {
        "webhook_url": None,
        "webhook_threshold": "HIGH",
        "pentestdb_url": None,
        "pentestdb_token": None,
    },

    "profiles": {
        "recon": {
            "description": "Passive reconnaissance only - no active probes",
            "threads": 5,
            "rate": 50,
            "no_intrusive": True,
        },
        "active": {
            "description": "Passive + active recon - no vulnerability scanning",
            "threads": 5,
            "rate": 50,
            "no_intrusive": True,
        },
        "full": {
            "description": "Complete scan - all phases enabled",
            "threads": 5,
            "rate": 50,
            "no_intrusive": False,
        },
        "stealth": {
            "description": "Full scan but slow and quiet",
            "threads": 2,
            "rate": 10,
            "delay": 0.5,
            "no_intrusive": True,
        },
        "aggressive": {
            "description": "Fast, intrusive, maximum findings",
            "threads": 10,
            "rate": 100,
            "delay": 0.0,
            "no_intrusive": False,
        },
    },
}


# ═════════════════════════════════════════════════════════════════════════════
# CONFIGURATION LOADER
# ═════════════════════════════════════════════════════════════════════════════

def expand_env_vars(value: Any) -> Any:
    """Recursively expand ${VAR} and $VAR in strings. Supports ${HOME}, ${USER}, etc."""
    if isinstance(value, str):
        # Expand environment variables
        return os.path.expandvars(value)
    elif isinstance(value, dict):
        return {k: expand_env_vars(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [expand_env_vars(item) for item in value]
    return value


def load_config_file(path: str) -> Dict[str, Any]:
    """Load a YAML config file. Returns empty dict if file doesn't exist or YAML not installed."""
    if not HAS_YAML:
        logger.warning("PyYAML not installed - config files not supported")
        return {}

    try:
        path_obj = Path(path)
        if not path_obj.exists():
            logger.debug(f"Config file not found: {path}")
            return {}

        if not path_obj.is_file():
            logger.warning(f"Config path is not a file: {path}")
            return {}

        with open(path_obj, 'r') as f:
            data = yaml.safe_load(f)

        if data is None:
            logger.debug(f"Config file is empty: {path}")
            return {}

        logger.info(f"Loaded config from: {path}")
        return expand_env_vars(data)

    except yaml.YAMLError as e:
        logger.error(f"YAML parse error in {path}: {e}")
        return {}
    except IOError as e:
        logger.error(f"Error reading config file {path}: {e}")
        return {}
    except Exception as e:
        logger.error(f"Unexpected error loading config {path}: {e}")
        return {}


def find_config_files() -> List[str]:
    """Find config files in standard locations (don't load, just find them)."""
    candidates = [
        Path.home() / ".webrecon-config.yaml",
        Path.home() / ".webrecon" / "config.yaml",
        Path.cwd() / "webrecon-config.yaml",
        Path.cwd() / ".webrecon-config.yaml",
    ]

    found = []
    for path in candidates:
        if path.exists() and path.is_file():
            found.append(str(path))
            logger.debug(f"Found config file: {path}")

    return found


def merge_configs(base: Dict, override: Dict) -> Dict:
    """
    Recursively merge override config into base config.
    Values in override take precedence over base.
    """
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursively merge nested dicts
            result[key] = merge_configs(result[key], value)
        else:
            # Override with new value
            result[key] = value

    return result


def get_nested(config: Dict, path: str, default: Any = None) -> Any:
    """
    Get a nested config value using dot notation.
    Example: get_nested(cfg, 'scanning.threads', 5)
    """
    keys = path.split('.')
    value = config

    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return default

    return value


def set_nested(config: Dict, path: str, value: Any) -> Dict:
    """
    Set a nested config value using dot notation.
    Example: set_nested(cfg, 'scanning.threads', 10)
    """
    keys = path.split('.')
    current = config

    for key in keys[:-1]:
        if key not in current:
            current[key] = {}
        current = current[key]

    current[keys[-1]] = value
    return config


class ConfigManager:
    """Manages loading and merging configurations from multiple sources."""

    def __init__(self, explicit_config: Optional[str] = None, verbose: bool = False):
        """
        Initialize config manager.

        Args:
            explicit_config: Path to explicit config file (highest priority)
            verbose: Enable debug logging
        """
        self.explicit_config = explicit_config
        self.verbose = verbose
        self.config: Dict[str, Any] = {}
        self._load_all()

    def _load_all(self):
        """Load and merge all config sources in priority order."""
        # Start with defaults
        self.config = DEFAULT_CONFIG.copy()

        # Load user global config
        user_config_path = Path.home() / ".webrecon-config.yaml"
        if user_config_path.exists():
            user_config = load_config_file(str(user_config_path))
            if user_config:
                self.config = merge_configs(self.config, user_config)
                if self.verbose:
                    logger.debug(f"Merged user config: {user_config_path}")

        # Load project-level config
        project_config_path = Path.cwd() / "webrecon-config.yaml"
        if project_config_path.exists():
            project_config = load_config_file(str(project_config_path))
            if project_config:
                self.config = merge_configs(self.config, project_config)
                if self.verbose:
                    logger.debug(f"Merged project config: {project_config_path}")

        # Load explicit config file (highest priority)
        if self.explicit_config:
            explicit = load_config_file(self.explicit_config)
            if explicit:
                self.config = merge_configs(self.config, explicit)
                if self.verbose:
                    logger.debug(f"Merged explicit config: {self.explicit_config}")

        # Expand any remaining env vars
        self.config = expand_env_vars(self.config)

    def get(self, key: str, default: Any = None) -> Any:
        """Get config value using dot notation. Example: cfg.get('scanning.threads', 5)"""
        return get_nested(self.config, key, default)

    def set(self, key: str, value: Any):
        """Set config value using dot notation. Example: cfg.set('scanning.threads', 10)"""
        self.config = set_nested(self.config, key, value)

    def get_profile(self, profile_name: str) -> Dict[str, Any]:
        """Get a scan profile from config."""
        profiles = self.config.get("profiles", {})
        if profile_name in profiles:
            return profiles[profile_name]
        return {}

    def to_dict(self) -> Dict[str, Any]:
        """Return entire config as dict."""
        return self.config.copy()

    def __repr__(self) -> str:
        import json
        return json.dumps(self.config, indent=2, default=str)


# ═════════════════════════════════════════════════════════════════════════════
# CLI HELPER
# ═════════════════════════════════════════════════════════════════════════════

def print_config(config_dict: Dict[str, Any]):
    """Pretty-print configuration."""
    if not HAS_YAML:
        import json
        print(json.dumps(config_dict, indent=2, default=str))
    else:
        print(yaml.dump(config_dict, default_flow_style=False, sort_keys=False))


def validate_config(config: ConfigManager) -> bool:
    """
    Validate configuration. Returns True if valid, False otherwise.
    Logs warnings for issues found.
    """
    valid = True

    # Check scanning section
    threads = config.get("scanning.threads", 5)
    if not isinstance(threads, int) or threads < 1:
        logger.warning(f"Invalid scanning.threads: {threads}, using default 5")
        config.set("scanning.threads", 5)
        valid = False

    timeout = config.get("scanning.timeout", 10)
    if not isinstance(timeout, int) or timeout < 1:
        logger.warning(f"Invalid scanning.timeout: {timeout}, using default 10")
        config.set("scanning.timeout", 10)
        valid = False

    # Check wordlist paths exist
    wordlists = config.get("scanning.wordlists", {})
    for name, path in wordlists.items():
        if path and not Path(path).exists():
            logger.warning(f"Wordlist not found: {name} → {path}")
            valid = False

    return valid


if __name__ == "__main__":
    # Test config loading
    logging.basicConfig(level=logging.DEBUG)

    print("=== Default Config ===")
    cfg = ConfigManager()
    print(f"Threads: {cfg.get('scanning.threads')}")
    print(f"Timeout: {cfg.get('scanning.timeout')}")
    print(f"\nProfiles: {list(cfg.config.get('profiles', {}).keys())}")
