"""
Pytest configuration and shared fixtures for web_app tests.

Provides:
- Mock HTTP responses for session testing
- Temporary config files
- Temporary directories and state files
- Mock logger
"""

import os
import json
import pytest
import tempfile
import logging
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from io import StringIO


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files.

    Returns:
        str: Path to temporary directory. Automatically cleaned up after test.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def temp_state_file(temp_dir):
    """Create a temporary state file path.

    Returns:
        str: Path to state file (doesn't exist yet).
    """
    return os.path.join(temp_dir, "state.json")


@pytest.fixture
def temp_config_file(temp_dir):
    """Create a temporary config file path.

    Returns:
        str: Path to config file (doesn't exist yet).
    """
    return os.path.join(temp_dir, "config.yaml")


@pytest.fixture
def sample_yaml_config(temp_config_file):
    """Create a sample YAML config file.

    Returns:
        str: Path to created config file with sample content.
    """
    config_content = """
scanning:
  threads: 10
  timeout: 15
  rate: 100
  verbose: true
  wordlists:
    common: /path/to/common.txt
    subdomains: /path/to/subdomains.txt

credentials:
  generic:
    - user: admin
      password: admin

reporting:
  format: json
  html_theme: dark

integrations:
  webhook_url: https://discord.com/api/webhooks/123/abc
  webhook_threshold: HIGH
  pentestdb_url: https://pentestdb.local
  pentestdb_token: secret_token
"""
    with open(temp_config_file, "w") as f:
        f.write(config_content)
    return temp_config_file


@pytest.fixture
def sample_state_file(temp_state_file):
    """Create a sample state file with completed phases.

    Returns:
        str: Path to created state file.
    """
    state_data = {
        "target": "example.com",
        "done": ["passive", "dns_security"],
        "start": "2025-01-01T00:00:00",
        "updated": "2025-01-01T01:00:00"
    }
    with open(temp_state_file, "w") as f:
        json.dump(state_data, f)
    return temp_state_file


@pytest.fixture
def sample_scope_file(temp_dir):
    """Create a sample scope file with domains and CIDRs.

    Returns:
        str: Path to created scope file.
    """
    scope_path = os.path.join(temp_dir, "scope.txt")
    scope_content = """# Scope file for testing
# IPv4 CIDR blocks
192.168.1.0/24
10.0.0.0/8

# IPv6 CIDR blocks
2001:db8::/32

# Domains
example.com
*.example.com
internal.local
*.internal.local
"""
    with open(scope_path, "w") as f:
        f.write(scope_content)
    return scope_path


@pytest.fixture
def mock_requests_response():
    """Create a mock requests.Response object.

    Returns:
        function: Factory function to create mock responses with custom status/content.
    """
    def _create_response(status_code=200, text="", json_data=None, headers=None):
        response = Mock()
        response.status_code = status_code
        response.text = text
        response.content = text.encode()
        response.headers = headers or {}
        response.url = "http://example.com"

        if json_data is not None:
            response.json.return_value = json_data
        else:
            response.json.side_effect = ValueError("No JSON")

        return response

    return _create_response


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing.

    Returns:
        Mock: Mock logger object with common methods.
    """
    logger = Mock(spec=logging.Logger)
    logger.debug = Mock()
    logger.info = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.exception = Mock()
    return logger


@pytest.fixture
def mock_config():
    """Create a mock ConfigManager-like object.

    Returns:
        Mock: Mock config object with common attributes.
    """
    config = Mock()
    config.target = "example.com"
    config.threads = 5
    config.timeout = 10
    config.user_agent = "Mozilla/5.0"
    config.proxy = None
    config.cookie = None
    config.extra_headers = []
    config.verbose = False
    config.webhook_url = None
    config.webhook_threshold = "HIGH"
    config.pentestdb_url = None
    config.pentestdb_token = None
    config.auth_check_url = None
    config.auth_check_text = None
    config.rate = 50
    config.delay = 0.0
    return config


@pytest.fixture
def caplog_handler():
    """Create a caplog-like handler for capturing logs during tests.

    Returns:
        StringIO: String buffer containing log output.
    """
    log_buffer = StringIO()
    handler = logging.StreamHandler(log_buffer)
    handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
    return log_buffer, handler


@pytest.fixture
def isolated_filesystem(temp_dir):
    """Provide an isolated filesystem context for tests.

    Returns:
        str: Path to isolated temp directory.
    """
    original_cwd = os.getcwd()
    try:
        os.chdir(temp_dir)
        yield temp_dir
    finally:
        os.chdir(original_cwd)


@pytest.fixture(autouse=True)
def reset_requests_mock():
    """Auto-reset requests mocks between tests."""
    with patch('requests.Session.request'):
        yield


@pytest.fixture
def mock_http_session(mock_requests_response):
    """Create a mock HTTP session for testing.

    Returns:
        Mock: Mock requests.Session with configurable responses.
    """
    session = Mock()

    # Default successful response
    session.request.return_value = mock_requests_response(status_code=200, text="OK")
    session.get.return_value = mock_requests_response(status_code=200, text="OK")
    session.post.return_value = mock_requests_response(status_code=200, text="OK")
    session.headers = {}
    session.cookies = Mock()
    session.cookies.set = Mock()
    session.proxies = {}

    return session


@pytest.fixture
def mock_file_system(temp_dir):
    """Provide filesystem mocking utilities.

    Returns:
        dict: Dictionary with helper functions for file operations.
    """
    def create_file(name, content=""):
        path = os.path.join(temp_dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    def file_exists(name):
        return os.path.exists(os.path.join(temp_dir, name))

    def read_file(name):
        with open(os.path.join(temp_dir, name), "r") as f:
            return f.read()

    return {
        "create": create_file,
        "exists": file_exists,
        "read": read_file,
        "root": temp_dir
    }


# Pytest options and configuration

def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: unit tests")
    config.addinivalue_line("markers", "integration: integration tests")
    config.addinivalue_line("markers", "slow: slow tests")
    config.addinivalue_line("markers", "mock_network: tests that mock network calls")


@pytest.fixture(scope="session")
def test_data_dir():
    """Provide path to test data directory.

    Returns:
        str: Path to test data directory (created if doesn't exist).
    """
    test_dir = Path(__file__).parent / "data"
    test_dir.mkdir(exist_ok=True)
    return str(test_dir)
