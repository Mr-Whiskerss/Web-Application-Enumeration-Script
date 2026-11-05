# Testing Guide for Web Application Enumeration Script

## Overview

This project includes comprehensive unit tests for all core modules. Tests are organized by functionality and include positive tests, negative tests, and edge cases.

## Test Structure

```
tests/
├── conftest.py              # Shared fixtures and pytest configuration
├── test_core/               # Core module tests
│   ├── test_config.py       # Configuration management tests
│   ├── test_findings.py     # Finding tracking and reporting tests
│   ├── test_state.py        # Scan state and scope checking tests
│   ├── test_session.py      # HTTP session and rate limiting tests
│   └── test_discovery.py    # Discovery state tracking tests
└── pytest.ini              # Pytest configuration
```

## Running Tests

### Install Dependencies

```bash
pip install -r requirements-dev.txt
```

### Run All Tests

```bash
pytest tests/
```

### Run Specific Test Module

```bash
pytest tests/test_core/test_config.py
pytest tests/test_core/test_findings.py
pytest tests/test_core/test_state.py
pytest tests/test_core/test_session.py
pytest tests/test_core/test_discovery.py
```

### Run Specific Test Class or Function

```bash
# Run all tests in a class
pytest tests/test_core/test_config.py::TestConfigManager

# Run a specific test
pytest tests/test_core/test_config.py::TestConfigManager::test_init_with_defaults
```

### Run Tests by Marker

```bash
# Run only unit tests
pytest -m unit

# Run only integration tests
pytest -m integration

# Run thread safety tests
pytest -m thread_safety

# Skip slow tests
pytest -m "not slow"
```

### Run with Coverage

```bash
pytest --cov=web_app.core --cov-report=html tests/test_core/
# Coverage report will be in htmlcov/index.html
```

### Run Tests in Parallel

```bash
pytest -n auto tests/
```

### Run Tests with Verbose Output

```bash
pytest -v tests/
```

### Run Tests with Detailed Failure Information

```bash
pytest --tb=long tests/
```

## Test Coverage

### test_config.py - Configuration Management (90+ tests)

Tests for:
- `expand_env_vars()` - Environment variable expansion
- `get_nested()` / `set_nested()` - Nested config access
- `merge_configs()` - Config merging logic
- `load_config_file()` - YAML file loading
- `validate_config()` - Configuration validation
- `ConfigManager` class - Main config manager
- Profile loading and retrieval

**Positive tests**: Default loading, YAML parsing, env var expansion
**Negative tests**: Missing files, invalid YAML, corrupted configs
**Edge cases**: Empty files, deeply nested configs, special characters

### test_findings.py - Finding Management (70+ tests)

Tests for:
- `Severity` enum - All severity levels
- `Finding` dataclass - Creation and data preservation
- `add_finding()` - Finding storage with deduplication
- `get_findings()` / `clear_findings()` - State access
- `save_findings()` - JSON serialization
- `webhook_notify()` - Discord/Slack webhook notifications
- `pentestdb_push()` - PentestDB integration
- Deduplication logic - Based on title, severity, and evidence hash

**Positive tests**: Adding valid findings, deduplication working
**Negative tests**: Invalid webhooks, network errors, auth failures
**Edge cases**: Empty evidence, very long descriptions, special characters

### test_state.py - Scan State Management (60+ tests)

Tests for:
- `ScanState` class - Phase marking and resumability
- `ScopeChecker` class - IPv4/IPv6/domain validation
- `DiscoveredState` class - URL and parameter tracking
- Thread safety of concurrent operations
- File I/O and state persistence

**ScanState tests**:
- Creating new state files
- Marking phases complete
- Resuming from saved state
- Handling corrupted state files
- State file cleanup

**ScopeChecker tests**:
- IPv4 CIDR matching
- IPv6 CIDR matching
- Domain exact and subdomain matching
- Wildcard domain matching
- DNS resolution fallback
- Case-insensitive matching

**DiscoveredState tests**:
- Adding URLs with endpoint extraction
- Adding parameters with query parsing
- Deduplication of URLs and parameters
- Thread-safe concurrent access
- URL filtering with limit

### test_session.py - HTTP Session Management (50+ tests)

Tests for:
- `RateLimitedSession` class - Rate limiting and backoff
- `make_session()` - Session creation with auth
- `detect_scheme()` - HTTP/HTTPS detection
- `revalidate_session()` - Auth check validation

**RateLimitedSession tests**:
- Successful requests
- 429 (Too Many Requests) handling
- 503 (Service Unavailable) handling
- Exponential backoff
- Retry-After header parsing (numeric and HTTP-date)
- Connection timeout/error handling
- Consecutive 429 counter reset after success
- Backoff window enforcement
- Backoff cap at 120 seconds

**make_session tests**:
- User agent configuration
- Proxy settings
- Cookie handling
- Custom headers
- Combined options

**detect_scheme tests**:
- HTTPS preference
- HTTP fallback
- Default to HTTP on failure
- Timeout handling

**revalidate_session tests**:
- No auth check configured
- Successful authentication
- Failed authentication
- Network errors and timeouts

### test_discovery.py - Discovery State Singleton (30+ tests)

Tests for:
- `DISCOVERED` singleton instance
- Data persistence and accumulation
- Thread safety across multiple phases
- Real-world scanning workflows

**Tests include**:
- Singleton persistence
- URL accumulation
- Parameter extraction
- Endpoint extraction
- Thread-safe concurrent operations
- Complex query parsing
- Limit enforcement

## Test Patterns Used

### Fixtures (from conftest.py)

- `temp_dir` - Temporary directory cleanup
- `temp_state_file` - Temporary state file path
- `temp_config_file` - Temporary config file path
- `sample_yaml_config` - Pre-configured YAML file
- `sample_state_file` - Pre-configured state file
- `sample_scope_file` - Pre-configured scope file
- `mock_requests_response` - Factory for mock HTTP responses
- `mock_logger` - Mock logger object
- `mock_config` - Mock config object
- `mock_http_session` - Mock HTTP session
- `mock_file_system` - File system helpers

### Mocking Strategies

- `unittest.mock.Mock` - For simple object mocking
- `unittest.mock.patch` - For patching imports/functions
- `unittest.mock.MagicMock` - For auto-spec mocking

### Test Organization

- **TestClassName** - Groups related tests
- **setup_method()** - Cleanup before each test
- **teardown_method()** - Cleanup after each test
- Clear docstrings - Each test explains its purpose

## Best Practices

1. **Isolation**: Each test is independent and can run in any order
2. **Speed**: Tests use mocks to avoid real network/file I/O
3. **Clarity**: Test names clearly describe what they test
4. **Coverage**: Include positive, negative, and edge case tests
5. **Fixtures**: Reuse fixtures for common setup/teardown
6. **Documentation**: Each test class/method has docstrings

## Common Test Scenarios

### Testing Config Merging

```python
def test_merge_nested_dicts(self):
    """Test merging nested dictionaries."""
    base = {"settings": {"threads": 5, "timeout": 10}}
    override = {"settings": {"threads": 20}}
    result = merge_configs(base, override)
    assert result["settings"]["threads"] == 20
    assert result["settings"]["timeout"] == 10
```

### Testing Thread Safety

```python
def test_thread_safety(self):
    """Test that state is thread-safe."""
    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(state.urls) > 0  # No corruption
```

### Testing with Mocked Network

```python
@patch('web_app.core.findings.requests.post')
def test_webhook_notify(self, mock_post):
    """Test webhook notification."""
    mock_post.return_value.status_code = 204
    webhook_notify(finding, config)
    assert mock_post.called
```

## Continuous Integration

Tests can be integrated into CI/CD:

```yaml
# Example GitHub Actions workflow
- name: Run tests
  run: pytest tests/ --cov=web_app.core --cov-report=xml

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.xml
```

## Debugging Tests

### Verbose Output

```bash
pytest -v -s tests/test_core/test_config.py::TestConfigManager::test_init_with_defaults
```

### Drop Into Debugger

```python
def test_something(self):
    import pdb; pdb.set_trace()  # Execution stops here
    # ... test code
```

### Print Statements

```bash
pytest -s tests/  # -s shows print output
```

### Detailed Tracebacks

```bash
pytest --tb=long tests/
```

## Extending Tests

### Adding New Tests

1. Create test file in appropriate `test_core/` directory
2. Import module under test
3. Create `Test*` classes
4. Write `test_*` methods
5. Use fixtures from `conftest.py`
6. Add docstrings explaining test purpose

### Adding New Fixtures

1. Add fixture to `tests/conftest.py`
2. Use `@pytest.fixture` decorator
3. Use type hints for clarity
4. Document fixture purpose in docstring

## Performance Considerations

- Tests use mocks instead of real I/O
- Most tests complete in < 100ms
- Parallel execution with `-n auto` supported
- No external network calls required
- No test data files needed

## Known Limitations

- YAML parser requires PyYAML library
- Some tests require `mock` library (included in Python 3.3+)
- Thread safety tests may behave differently on different systems
- DNS resolution tests require socket module

## Troubleshooting

### ImportError for web_app modules

```python
# Add project root to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
```

### Fixture not found

- Ensure conftest.py is in tests/ directory
- Fixture name must match parameter name in test function
- Fixtures in conftest.py are auto-discovered

### Mock not working

- Use `@patch` for function-level patches
- Use `patch.object()` for class methods
- Ensure patch path matches import path

### State pollution between tests

- Use `setup_method()` to reset state
- Fixtures with `temp_dir` auto-cleanup
- Use `clear_findings()` for global state reset

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Python unittest.mock](https://docs.python.org/3/library/unittest.mock.html)
- [Pytest Fixtures](https://docs.pytest.org/en/stable/fixture.html)
