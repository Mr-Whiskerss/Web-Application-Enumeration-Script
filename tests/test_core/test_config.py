"""
Unit tests for config module.

Tests ConfigManager, load_config_file, merge_configs, validate_config, and expand_env_vars.
"""

import os
import pytest
import tempfile
from unittest.mock import patch, MagicMock
from pathlib import Path

# Import from config module
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from config import (
    ConfigManager,
    load_config_file,
    merge_configs,
    validate_config,
    expand_env_vars,
    get_nested,
    set_nested,
    find_config_files,
    DEFAULT_CONFIG,
)


class TestExpandEnvVars:
    """Test expand_env_vars function."""

    def test_expand_simple_env_var(self):
        """Test expanding a simple environment variable."""
        os.environ["TEST_VAR"] = "test_value"
        result = expand_env_vars("${TEST_VAR}")
        assert result == "test_value"

    def test_expand_dollar_env_var(self):
        """Test expanding environment variable with $ prefix."""
        os.environ["TEST_VAR2"] = "another_value"
        result = expand_env_vars("$TEST_VAR2")
        assert result == "another_value"

    def test_expand_home_dir(self):
        """Test expanding ${HOME} to user home directory."""
        result = expand_env_vars("${HOME}/.config")
        assert result.startswith("/")
        assert ".config" in result

    def test_expand_env_vars_in_dict(self):
        """Test expanding environment variables in dictionary values."""
        os.environ["DB_HOST"] = "localhost"
        os.environ["DB_PORT"] = "5432"
        config = {
            "database": {
                "host": "${DB_HOST}",
                "port": "${DB_PORT}",
            }
        }
        result = expand_env_vars(config)
        assert result["database"]["host"] == "localhost"
        assert result["database"]["port"] == "5432"

    def test_expand_env_vars_in_list(self):
        """Test expanding environment variables in list items."""
        os.environ["PATH_VAR"] = "/usr/local/bin"
        config = ["${PATH_VAR}", "/usr/bin", "/bin"]
        result = expand_env_vars(config)
        assert result[0] == "/usr/local/bin"
        assert result[1] == "/usr/bin"

    def test_expand_env_vars_nested_structure(self):
        """Test expanding environment variables in deeply nested structure."""
        os.environ["API_KEY"] = "secret123"
        config = {
            "api": {
                "auth": {
                    "key": "${API_KEY}",
                    "endpoints": ["${API_KEY}/v1", "${API_KEY}/v2"]
                }
            }
        }
        result = expand_env_vars(config)
        assert result["api"]["auth"]["key"] == "secret123"
        assert result["api"]["auth"]["endpoints"][0] == "secret123/v1"

    def test_expand_nonexistent_env_var(self):
        """Test expanding nonexistent environment variable (returns empty)."""
        # os.path.expandvars returns the unexpanded string if var doesn't exist
        result = expand_env_vars("${NONEXISTENT_VAR_12345}")
        assert "${NONEXISTENT_VAR_12345}" in result or result == ""

    def test_expand_numeric_value_unchanged(self):
        """Test that numeric values remain unchanged."""
        result = expand_env_vars(42)
        assert result == 42

    def test_expand_boolean_unchanged(self):
        """Test that boolean values remain unchanged."""
        result = expand_env_vars(True)
        assert result is True


class TestGetNestedSetNested:
    """Test get_nested and set_nested functions."""

    def test_get_nested_simple(self):
        """Test getting a simple nested value."""
        config = {"a": {"b": {"c": "value"}}}
        result = get_nested(config, "a.b.c")
        assert result == "value"

    def test_get_nested_default(self):
        """Test getting nested value with default when key doesn't exist."""
        config = {"a": {"b": {}}}
        result = get_nested(config, "a.b.c", "default")
        assert result == "default"

    def test_get_nested_missing_intermediate(self):
        """Test getting nested value when intermediate key missing."""
        config = {"a": {}}
        result = get_nested(config, "a.b.c", "default")
        assert result == "default"

    def test_set_nested_simple(self):
        """Test setting a simple nested value."""
        config = {}
        set_nested(config, "a.b.c", "value")
        assert config["a"]["b"]["c"] == "value"

    def test_set_nested_overwrites_existing(self):
        """Test that set_nested overwrites existing values."""
        config = {"a": {"b": {"c": "old"}}}
        set_nested(config, "a.b.c", "new")
        assert config["a"]["b"]["c"] == "new"

    def test_set_nested_creates_intermediate_dicts(self):
        """Test that set_nested creates intermediate dictionaries."""
        config = {}
        set_nested(config, "deep.nested.value.path", "result")
        assert config["deep"]["nested"]["value"]["path"] == "result"


class TestMergeConfigs:
    """Test merge_configs function."""

    def test_merge_simple_override(self):
        """Test simple value override in merge."""
        base = {"a": 1, "b": 2}
        override = {"a": 10}
        result = merge_configs(base, override)
        assert result["a"] == 10
        assert result["b"] == 2

    def test_merge_nested_dicts(self):
        """Test merging nested dictionaries."""
        base = {"settings": {"threads": 5, "timeout": 10}}
        override = {"settings": {"threads": 20}}
        result = merge_configs(base, override)
        assert result["settings"]["threads"] == 20
        assert result["settings"]["timeout"] == 10

    def test_merge_deeply_nested(self):
        """Test merging deeply nested structures."""
        base = {
            "level1": {
                "level2": {
                    "level3": {"value": "original", "keep": "this"}
                }
            }
        }
        override = {"level1": {"level2": {"level3": {"value": "updated"}}}}
        result = merge_configs(base, override)
        assert result["level1"]["level2"]["level3"]["value"] == "updated"
        assert result["level1"]["level2"]["level3"]["keep"] == "this"

    def test_merge_preserves_base(self):
        """Test that merge doesn't modify original base dict."""
        base = {"a": {"b": 1}}
        override = {"a": {"c": 2}}
        result = merge_configs(base, override)
        assert "b" in result["a"]
        assert "c" in result["a"]
        assert base == {"a": {"b": 1}}  # Base unchanged

    def test_merge_adds_new_keys(self):
        """Test that merge adds new keys from override."""
        base = {"a": 1}
        override = {"b": 2, "c": 3}
        result = merge_configs(base, override)
        assert result["a"] == 1
        assert result["b"] == 2
        assert result["c"] == 3

    def test_merge_replaces_non_dict_with_dict(self):
        """Test merging replaces non-dict with dict."""
        base = {"config": "string_value"}
        override = {"config": {"nested": "value"}}
        result = merge_configs(base, override)
        assert isinstance(result["config"], dict)
        assert result["config"]["nested"] == "value"


class TestLoadConfigFile:
    """Test load_config_file function."""

    def test_load_nonexistent_file(self, temp_config_file):
        """Test loading nonexistent config file returns empty dict."""
        result = load_config_file(temp_config_file)
        assert result == {}

    def test_load_valid_yaml_config(self, sample_yaml_config):
        """Test loading valid YAML config file."""
        result = load_config_file(sample_yaml_config)
        assert result["scanning"]["threads"] == 10
        assert result["scanning"]["timeout"] == 15

    def test_load_empty_yaml_file(self, temp_config_file):
        """Test loading empty YAML file."""
        with open(temp_config_file, "w") as f:
            f.write("")
        result = load_config_file(temp_config_file)
        assert result == {}

    def test_load_yaml_with_comments(self, temp_config_file):
        """Test loading YAML file with comments."""
        yaml_content = """# This is a comment
scanning:
  threads: 5  # Inline comment
  timeout: 10
"""
        with open(temp_config_file, "w") as f:
            f.write(yaml_content)
        result = load_config_file(temp_config_file)
        assert result["scanning"]["threads"] == 5

    def test_load_invalid_yaml(self, temp_config_file):
        """Test loading invalid YAML returns empty dict."""
        with open(temp_config_file, "w") as f:
            f.write("invalid: yaml: syntax: here:")
        result = load_config_file(temp_config_file)
        assert result == {}

    def test_load_directory_path(self, temp_dir):
        """Test loading directory path returns empty dict."""
        result = load_config_file(temp_dir)
        assert result == {}

    @patch('config.HAS_YAML', False)
    def test_load_without_yaml_installed(self, temp_config_file):
        """Test that load returns empty dict when YAML not installed."""
        result = load_config_file(temp_config_file)
        assert result == {}


class TestFindConfigFiles:
    """Test find_config_files function."""

    def test_find_config_files_in_home(self, temp_dir):
        """Test finding config file in home directory."""
        with patch('pathlib.Path.home') as mock_home:
            mock_home_path = Path(temp_dir)
            mock_home.return_value = mock_home_path

            # Create config file in temp home
            config_file = mock_home_path / ".webrecon-config.yaml"
            config_file.write_text("scanning:\n  threads: 5")

            result = find_config_files()
            assert any(".webrecon-config.yaml" in str(p) for p in result)

    def test_find_config_files_empty_when_none_exist(self):
        """Test find_config_files returns empty list when no configs exist."""
        with patch('pathlib.Path.home') as mock_home, \
             patch('pathlib.Path.cwd') as mock_cwd:
            mock_home.return_value = Path("/nonexistent/home")
            mock_cwd.return_value = Path("/nonexistent/cwd")
            result = find_config_files()
            assert result == []


class TestValidateConfig:
    """Test validate_config function."""

    def test_validate_valid_config(self, mock_config):
        """Test validation of valid config."""
        cfg = ConfigManager()
        result = validate_config(cfg)
        assert result is True

    def test_validate_invalid_threads(self, temp_dir):
        """Test validation fails for invalid thread count."""
        cfg = ConfigManager()
        cfg.set("scanning.threads", 0)
        result = validate_config(cfg)
        assert result is False

    def test_validate_invalid_timeout(self, temp_dir):
        """Test validation fails for invalid timeout."""
        cfg = ConfigManager()
        cfg.set("scanning.timeout", -1)
        result = validate_config(cfg)
        assert result is False

    def test_validate_nonexistent_wordlist(self, temp_dir):
        """Test validation warns about nonexistent wordlist paths."""
        cfg = ConfigManager()
        cfg.set("scanning.wordlists.common", "/nonexistent/path.txt")
        result = validate_config(cfg)
        assert result is False

    def test_validate_config_self_corrects_threads(self):
        """Test that validation corrects invalid thread count."""
        cfg = ConfigManager()
        cfg.set("scanning.threads", -5)
        validate_config(cfg)
        assert cfg.get("scanning.threads") == 5

    def test_validate_config_self_corrects_timeout(self):
        """Test that validation corrects invalid timeout."""
        cfg = ConfigManager()
        cfg.set("scanning.timeout", 0)
        validate_config(cfg)
        assert cfg.get("scanning.timeout") == 10


class TestConfigManager:
    """Test ConfigManager class."""

    def test_init_with_defaults(self):
        """Test ConfigManager initializes with default config."""
        cfg = ConfigManager()
        assert cfg.config is not None
        assert "scanning" in cfg.config
        assert "credentials" in cfg.config

    def test_init_with_explicit_config(self, sample_yaml_config):
        """Test ConfigManager initializes with explicit config file."""
        cfg = ConfigManager(explicit_config=sample_yaml_config)
        assert cfg.get("scanning.threads") == 10
        assert cfg.get("scanning.timeout") == 15

    def test_get_with_dot_notation(self):
        """Test getting config values with dot notation."""
        cfg = ConfigManager()
        threads = cfg.get("scanning.threads")
        assert isinstance(threads, int)

    def test_get_with_default(self):
        """Test get returns default for missing keys."""
        cfg = ConfigManager()
        result = cfg.get("nonexistent.key", "default_value")
        assert result == "default_value"

    def test_set_with_dot_notation(self):
        """Test setting config values with dot notation."""
        cfg = ConfigManager()
        cfg.set("scanning.threads", 20)
        assert cfg.get("scanning.threads") == 20

    def test_get_profile(self):
        """Test getting a scan profile."""
        cfg = ConfigManager()
        profile = cfg.get_profile("aggressive")
        assert profile is not None
        assert "threads" in profile

    def test_get_nonexistent_profile(self):
        """Test getting nonexistent profile returns empty dict."""
        cfg = ConfigManager()
        profile = cfg.get_profile("nonexistent_profile")
        assert profile == {}

    def test_to_dict(self):
        """Test converting config to dictionary."""
        cfg = ConfigManager()
        config_dict = cfg.to_dict()
        assert isinstance(config_dict, dict)
        assert "scanning" in config_dict

    def test_to_dict_returns_copy(self):
        """Test that to_dict returns a copy not reference."""
        cfg = ConfigManager()
        dict1 = cfg.to_dict()
        dict1["scanning"]["threads"] = 999
        dict2 = cfg.to_dict()
        assert dict2["scanning"]["threads"] != 999

    def test_config_repr(self):
        """Test config __repr__ returns JSON string."""
        cfg = ConfigManager()
        repr_str = repr(cfg)
        assert isinstance(repr_str, str)
        assert "scanning" in repr_str

    def test_merge_order_explicit_overrides_defaults(self, sample_yaml_config):
        """Test that explicit config overrides defaults."""
        cfg = ConfigManager(explicit_config=sample_yaml_config)
        assert cfg.get("scanning.threads") == 10  # From explicit config, not default

    def test_env_var_expansion_in_config(self, temp_config_file):
        """Test environment variable expansion in loaded config."""
        os.environ["TEST_THREAD_COUNT"] = "25"
        config_content = "scanning:\n  threads: ${TEST_THREAD_COUNT}"
        with open(temp_config_file, "w") as f:
            f.write(config_content)

        cfg = ConfigManager(explicit_config=temp_config_file)
        # Note: YAML load happens before env var expansion
        assert cfg.get("scanning.threads") == 25 or cfg.get("scanning.threads") == "$TEST_THREAD_COUNT"

    def test_verbose_mode(self, sample_yaml_config):
        """Test ConfigManager with verbose mode enabled."""
        cfg = ConfigManager(explicit_config=sample_yaml_config, verbose=True)
        assert cfg.verbose is True
        assert cfg.config is not None


class TestIntegration:
    """Integration tests for config loading."""

    def test_full_config_loading_pipeline(self, temp_dir):
        """Test complete config loading pipeline with multiple sources."""
        # Create explicit config
        explicit_config_path = os.path.join(temp_dir, "explicit.yaml")
        with open(explicit_config_path, "w") as f:
            f.write("scanning:\n  threads: 100\n  timeout: 20")

        cfg = ConfigManager(explicit_config=explicit_config_path)

        # Verify defaults are present
        assert "credentials" in cfg.config
        assert "profiles" in cfg.config

        # Verify explicit overrides
        assert cfg.get("scanning.threads") == 100
        assert cfg.get("scanning.timeout") == 20

    def test_config_with_nested_profiles(self):
        """Test loading and using nested profiles."""
        cfg = ConfigManager()
        profiles = cfg.config.get("profiles", {})

        # Verify all expected profiles exist
        expected_profiles = ["recon", "active", "full", "stealth", "aggressive"]
        for profile_name in expected_profiles:
            assert profile_name in profiles
            profile = profiles[profile_name]
            assert "threads" in profile
            assert "rate" in profile
