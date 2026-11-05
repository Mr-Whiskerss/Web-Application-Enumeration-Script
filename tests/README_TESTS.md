# Test Suite Documentation

This directory contains comprehensive unit tests for the Web Application Enumeration Script. Tests are organized by component and use mocking to ensure they're fast, independent, and don't require external tools or network access.

## Overview

The test suite covers:

1. **Integration Tests** (`test_integrations.py`) - Webhook and PentestDB notification systems
2. **Phase Tests** (`test_phases_sample.py`) - Representative scanning phases (passive, active, vulnerability)

All tests use `pytest` and `unittest.mock` for mocking external dependencies.

## Test Files

### test_integrations.py

Tests for webhook and PentestDB integration modules. All HTTP calls are mocked.

**Coverage:**

- **`TestWebhookNotify`** - Webhook notification system (Discord and Slack)
  - Discord embed formatting with severity-based colors
  - Slack text message formatting
  - HTTP error handling (400, 500 status codes)
  - Network timeouts and connection errors
  - Proxy configuration
  - Description truncation to 1500 characters
  - Severity color mapping verification
  - Tests when webhook_url is not configured (early return)

- **`TestPentestdbPush`** - PentestDB API integration
  - Successful finding submission to /api/findings endpoint
  - Bearer token authentication in headers
  - Payload structure with all finding fields
  - Endpoint URL construction with trailing slash handling
  - HTTP error handling (400, 500 status codes)
  - Network timeouts and connection errors
  - Tests when pentestdb_url is not configured
  - Severity level mapping for all severities
  - 10-second timeout verification (different from webhook's 5 seconds)

- **`TestIntegrationInteraction`** - Cross-integration tests
  - Both webhook and pentestdb triggered for same finding
  - Failure isolation (webhook failure doesn't prevent pentestdb)

**Key Features:**

- Mocked HTTP requests using `unittest.mock.patch`
- All severity levels tested (INFO, LOW, MEDIUM, HIGH, CRITICAL)
- Error handling and graceful degradation
- Configuration validation
- Docstrings explaining what each test verifies

### test_phases_sample.py

Tests for representative scanning phases with mocked tool execution and file I/O.

**Coverage:**

- **`TestPhasePassiveDns`** - Passive DNS reconnaissance
  - nslookup execution for DNS lookup
  - WHOIS parsing for domain creation date
  - Recently registered domain detection (< 1 year old)
  - IPv4 and domain target handling
  - Phase skip behavior when already done
  - Severity set to MEDIUM for recent domains

- **`TestPhasePortScan`** - Active port scanning with nmap
  - Tool availability checking (skip when nmap not installed)
  - Common ports list (when full_ports=False)
  - Full port range scanning (when full_ports=True)
  - HTTP methods NSE script execution
  - Sudo elevation for raw socket access
  - Service version detection (-sV flag)
  - State management (phase marked as done)

- **`TestPhaseNuclei`** - Vulnerability scanning with nuclei templates
  - Tool availability checking
  - JSONL output parsing and finding generation
  - Severity mapping (info→INFO, low→LOW, etc.)
  - Malformed JSON line handling (graceful skip)
  - Missing output file handling
  - Command construction with:
    - Target URL
    - Severity filtering
    - Threading and rate limiting
    - Proxy configuration
    - Custom headers
    - No-intrusive tag exclusion

**Key Features:**

- Mocked subprocess calls (`run_cmd`)
- Mocked file I/O (`builtins.open`)
- Mocked tool availability checks
- State file management with `ScanState`
- JSONL output parsing verification
- Multiple finding generation from single phase
- Error tolerance (malformed input handling)

## Running the Tests

### Prerequisites

Install test dependencies:

```bash
pip install pytest pytest-cov requests
```

The script requires:
- `pytest` - Test framework
- `requests` - For mocking HTTP library
- `pytest-cov` (optional) - For coverage reports

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test File

```bash
pytest tests/test_integrations.py -v
pytest tests/test_phases_sample.py -v
```

### Run Specific Test Class

```bash
pytest tests/test_integrations.py::TestWebhookNotify -v
pytest tests/test_phases_sample.py::TestPhaseNuclei -v
```

### Run Specific Test

```bash
pytest tests/test_integrations.py::TestWebhookNotify::test_webhook_discord_success -v
```

### Run with Coverage Report

```bash
pytest tests/ -v --cov=web_app --cov-report=html
```

### Run with Output

```bash
pytest tests/ -v -s
```

The `-s` flag captures and displays print statements from your code.

### Run Tests Matching a Pattern

```bash
pytest tests/ -k "webhook" -v      # Run tests containing "webhook"
pytest tests/ -k "nuclei" -v       # Run tests containing "nuclei"
pytest tests/ -k "error" -v        # Run tests containing "error"
```

## Test Configuration

The `conftest.py` file provides pytest fixtures used by all tests:

- **`mock_config`** - Mock ScanConfig with common attributes
- **`mock_state`** - Mock ScanState with temp directory
- **`mock_requests_response`** - Factory for mock HTTP responses
- **`mock_http_session`** - Mock requests.Session
- **`temp_dir`** - Temporary directory (auto-cleanup)
- **`mock_logger`** - Mock logger object
- **Markers** - @pytest.mark.unit, @pytest.mark.integration, @pytest.mark.slow, @pytest.mark.mock_network

## Test Design Principles

All tests follow these principles:

1. **Isolation** - Each test is independent and can run in any order
2. **Mocking** - All external calls (HTTP, subprocess, file I/O) are mocked
3. **Speed** - Tests complete in milliseconds (no network/tool delays)
4. **Documentation** - Each test has a docstring explaining what it verifies
5. **Coverage** - Happy path, error cases, and edge cases tested
6. **Clarity** - Test names clearly describe what is being tested
7. **Maintainability** - Fixtures reduce duplication, mock configuration is centralized

## Test Structure

Each test follows a consistent structure:

```python
def test_descriptive_name(self, fixture1, fixture2):
    """Docstring explaining what is tested and what is verified."""
    # ARRANGE - Set up test data and mocks
    mock_config.webhook_url = "https://discord.com/api/webhooks/123/abc"
    mock_response = Mock(status_code=200)
    mock_post.return_value = mock_response
    
    # ACT - Execute the function under test
    webhook.webhook_notify(finding, mock_config)
    
    # ASSERT - Verify the results
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    assert "embeds" in kwargs["json"]
```

## What Is NOT Tested

The following are out of scope for these unit tests:

- **Integration Tests** - Multiple components working together with real HTTP/file I/O
- **End-to-End Tests** - Full scan workflows with real targets
- **System Tools** - Actual nmap, nuclei, ffuf execution (these are mocked)
- **Network Calls** - Real connections to webhook URLs or PentestDB servers
- **File System** - Tests use temporary directories; production file structure not tested

For integration/E2E tests, consider:
- Setting up a test environment with dummy targets
- Using Docker containers for isolated testing
- Creating separate test suite for verified environments

## Extending the Tests

### Adding a New Phase Test

1. Create a test class for the phase in `test_phases_sample.py`:

```python
class TestPhaseNewPhase:
    """Test suite for new_phase scanning phase.
    
    Tests:
    - Thing 1
    - Thing 2
    """
    
    @pytest.fixture
    def mock_config(self):
        """Create mock config."""
        config = Mock(spec=ScanConfig)
        # Configure as needed
        return config
    
    @patch('web_app.phases.new_phase.run_cmd')
    @patch('web_app.phases.new_phase._tool_ok')
    def test_basic_functionality(self, mock_tool_ok, mock_run_cmd, mock_config, temp_dir):
        """Test basic functionality."""
        # Arrange
        mock_tool_ok.return_value = True
        
        # Act
        from web_app.phases.new_phase import phase_new_phase
        phase_new_phase("target.com", mock_config, temp_dir + "/report.md", mock_state)
        
        # Assert
        mock_run_cmd.assert_called_once()
```

2. Import required modules at top of file
3. Use fixtures from conftest.py
4. Mock external calls with @patch decorators
5. Follow Arrange-Act-Assert structure
6. Include docstrings explaining what is tested

### Adding a New Integration Test

1. Create a test class in `test_integrations.py`:

```python
class TestNewIntegration:
    """Test suite for new_integration module."""
    
    @patch('web_app.integrations.new_integration.requests.post')
    def test_success_case(self, mock_post, sample_finding, sample_config):
        """Test successful operation."""
        mock_response = Mock(status_code=200)
        mock_post.return_value = mock_response
        
        # Call integration function
        # Assert expectations
```

2. Follow the same patterns as existing tests
3. Mock HTTP calls using unittest.mock.patch
4. Test success, error, and edge cases
5. Include docstrings for clarity

## Continuous Integration

For CI/CD pipeline integration:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: |
    pip install -r requirements.txt pytest pytest-cov
    pytest tests/ -v --cov=web_app --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.xml
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'web_app'"

Ensure you're running pytest from the project root directory:

```bash
cd /home/dan/Personal_tools/Web-Application-Enumeration-Script
pytest tests/
```

### "Mock object not being used"

Verify the patch path matches where the function is USED, not where it's DEFINED:

```python
# If webhook_notify is imported in main.py:
@patch('web_app.main.requests.post')  # Patch where it's used
def test_function(self, mock_post):
    pass
```

### Tests passing but coverage incomplete

Some code might be inside conditional branches. Check:
- Tool availability checks (mocked as unavailable by default)
- Error handling paths (explicitly test error cases)
- Optional features (configure mock_config to enable them)

### "TypeError: __init__() missing required positional argument"

Verify fixtures are passed as parameters to test method:

```python
# Correct
def test_function(self, mock_config, temp_dir):
    pass

# Incorrect - missing parameters
def test_function(self):
    pass
```

## Summary

- **test_integrations.py** - 28 webhook tests, 20 pentestdb tests, 2 interaction tests = 50 tests
- **test_phases_sample.py** - 3 passive DNS tests, 4 port scan tests, 8 nuclei tests = 15 tests
- **Total** - 65 unit tests covering integrations and representative phases
- **All tests mock external dependencies** - No tools/network required
- **Independent and fast** - Can run in any order, complete in seconds
- **Well-documented** - Each test has docstring explaining its purpose

The test suite provides a solid foundation for regression testing and continuous integration. Expand with additional phase tests as the codebase evolves.
