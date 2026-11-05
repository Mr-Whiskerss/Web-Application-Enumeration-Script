# Quick Start Guide for Tests

## Setup (5 minutes)

### 1. Install Test Dependencies

```bash
cd /home/dan/Personal_tools/Web-Application-Enumeration-Script
pip install pytest requests
```

Optional for coverage reports:
```bash
pip install pytest-cov
```

### 2. Verify Installation

```bash
pytest --version
# pytest 7.x.x
```

---

## Running Tests

### Run Everything

```bash
pytest tests/ -v
```

**Expected Output:**
```
tests/test_integrations.py::TestWebhookNotify::test_webhook_discord_success PASSED
tests/test_integrations.py::TestWebhookNotify::test_webhook_slack_success PASSED
tests/test_integrations.py::TestWebhookNotify::test_webhook_with_proxy PASSED
...
tests/test_phases_sample.py::TestPhaseNuclei::test_nuclei_parses_jsonl_output PASSED
...

========================== 38 passed in 2.34s ==========================
```

### Run Integration Tests Only

```bash
pytest tests/test_integrations.py -v
```

**Expected:** 24 tests passed

### Run Phase Tests Only

```bash
pytest tests/test_phases_sample.py -v
```

**Expected:** 14 tests passed

### Run Tests by Name Pattern

```bash
# All webhook tests
pytest tests/ -k "webhook" -v

# All error handling tests
pytest tests/ -k "error" -v

# All timeout tests
pytest tests/ -k "timeout" -v
```

### Run with Coverage Report

```bash
pytest tests/ -v --cov=web_app --cov-report=html
# Report saved to htmlcov/index.html
```

---

## Test Categories

### Webhook Tests (11 tests)

Test Discord/Slack webhook notifications, error handling, and configuration:

```bash
pytest tests/test_integrations.py::TestWebhookNotify -v
```

### PentestDB Tests (10 tests)

Test finding submission to PentestDB API:

```bash
pytest tests/test_integrations.py::TestPentestdbPush -v
```

### Passive DNS Tests (4 tests)

Test passive DNS reconnaissance phase:

```bash
pytest tests/test_phases_sample.py::TestPhasePassiveDns -v
```

### Port Scan Tests (4 tests)

Test active port scanning phase:

```bash
pytest tests/test_phases_sample.py::TestPhasePortScan -v
```

### Nuclei Tests (8 tests)

Test vulnerability scanning phase:

```bash
pytest tests/test_phases_sample.py::TestPhaseNuclei -v
```

---

## Common Commands

### Run Single Test

```bash
pytest tests/test_integrations.py::TestWebhookNotify::test_webhook_discord_success -v
```

### Run with Detailed Output

```bash
# Show print statements and logging
pytest tests/ -v -s

# Very verbose output
pytest tests/ -vv

# Show local variables on failure
pytest tests/ -v -l
```

### Stop on First Failure

```bash
pytest tests/ -x
```

### Run N Most Recent Failures

```bash
pytest tests/ --lf    # Last failed
pytest tests/ --ff    # Failed first
```

### Parallel Execution (faster)

```bash
pip install pytest-xdist
pytest tests/ -v -n auto  # Use all CPU cores
```

---

## Understanding Test Output

### PASSED Test

```
tests/test_integrations.py::TestWebhookNotify::test_webhook_discord_success PASSED
```

The test ran successfully. All assertions passed.

### FAILED Test

```
tests/test_integrations.py::TestWebhookNotify::test_webhook_discord_success FAILED
```

An assertion or exception failed. See error details below.

### SKIPPED Test

```
tests/test_integrations.py::TestSomething::test_something SKIPPED
```

Test was skipped (e.g., missing optional dependency).

### Summary

```
========================== 38 passed in 2.34s ==========================
```

- **38 passed** - Number of passing tests
- **2.34s** - Total execution time

---

## Troubleshooting

### "No module named 'pytest'"

```bash
# Install pytest
pip install pytest

# Verify
pytest --version
```

### "No module named 'web_app'"

```bash
# Run from project root
cd /home/dan/Personal_tools/Web-Application-Enumeration-Script
pytest tests/

# Or add project to PYTHONPATH
export PYTHONPATH=/home/dan/Personal_tools/Web-Application-Enumeration-Script:$PYTHONPATH
pytest tests/
```

### "ModuleNotFoundError: No module named 'requests'"

```bash
pip install requests
```

### Tests fail with "mocked module not found"

Ensure conftest.py is in the tests/ directory.

```bash
ls tests/conftest.py
# Should exist
```

### Mock not being called

Check the patch path is where function is USED, not defined:

```python
# In test_integrations.py:
@patch('web_app.integrations.webhook.requests.post')  # Correct
def test_function(self, mock_post):
    pass
```

---

## What Each Test File Tests

### test_integrations.py

Tests external integrations with mocked HTTP:

| Test Class | Tests | Focus |
|------------|-------|-------|
| TestWebhookNotify | 11 | Discord/Slack webhook notifications |
| TestPentestdbPush | 10 | PentestDB API integration |
| TestIntegrationInteraction | 2 | Cross-integration behavior |
| **Total** | **24** | **Webhook & PentestDB** |

### test_phases_sample.py

Tests scanning phases with mocked tools:

| Test Class | Tests | Focus |
|------------|-------|-------|
| TestPhasePassiveDns | 4 | Passive DNS reconnaissance |
| TestPhasePortScan | 4 | Active port scanning |
| TestPhaseNuclei | 8 | Vulnerability scanning |
| **Total** | **14** | **Representative Phases** |

---

## Next Steps

### 1. Run All Tests

```bash
pytest tests/ -v
```

### 2. Check Coverage

```bash
pytest tests/ --cov=web_app --cov-report=term-missing
```

### 3. Add Your Own Tests

See the documentation in:
- `tests/README_TESTS.md` - Detailed test documentation
- `tests/TEST_SUMMARY.md` - Component-by-component breakdown

### 4. Integrate with CI/CD

Add to your CI pipeline to run tests on every commit.

---

## Tips

- **Run tests frequently** - After every change
- **Use -v flag** - Verbose output shows what's being tested
- **Use -k filter** - Run specific tests by name pattern
- **Check coverage** - Ensure new code is tested
- **Read docstrings** - Each test explains what it verifies
- **Follow patterns** - Use existing test structure as template

---

## Getting Help

For more information, see:

- `tests/README_TESTS.md` - Comprehensive test documentation
- `tests/TEST_SUMMARY.md` - Summary and metrics
- `tests/conftest.py` - Available fixtures
- Test docstrings - What each test verifies

---

## Quick Reference

```bash
# Install
pip install pytest requests pytest-cov

# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_integrations.py::TestWebhookNotify::test_webhook_discord_success -v

# Run by pattern
pytest tests/ -k "webhook" -v

# With coverage
pytest tests/ --cov=web_app --cov-report=html

# Stop on first failure
pytest tests/ -x

# Show print statements
pytest tests/ -v -s
```

---

## Summary

- **38 unit tests** for integrations and representative phases
- **All mocked** - No external tools/network required
- **Fast execution** - Complete in seconds
- **Well documented** - Each test has clear docstring
- **Easy to extend** - Follow existing patterns

Start testing today!
```bash
pytest tests/ -v
```
