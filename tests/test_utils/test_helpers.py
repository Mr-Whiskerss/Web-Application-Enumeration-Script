"""
Comprehensive unit tests for web_app.utils.helpers module.

Tests cover:
  - normalise(): URL parsing and path normalization
  - validate(): IPv4, IPv6, domain, and host:port validation
  - sanitise(): Input sanitization for shell safety
  - yes_no(): User prompt handling
  - diff_findings(): Comparison of findings against previous results
"""

import pytest
import json
import os
import tempfile
from unittest.mock import patch, MagicMock
from dataclasses import dataclass

# Import the functions to test
from web_app.utils.helpers import (
    normalise,
    validate,
    sanitise,
    yes_no,
    diff_findings,
)


# ═════════════════════════════════════════════════════════════════════════════
# TEST: normalise()
# ═════════════════════════════════════════════════════════════════════════════

class TestNormalise:
    """Test normalise() function for URL and path normalization."""

    def test_normalise_https_url(self):
        """normalise() extracts netloc from HTTPS URLs."""
        assert normalise("https://example.com/path") == "example.com"

    def test_normalise_http_url(self):
        """normalise() extracts netloc from HTTP URLs."""
        assert normalise("http://example.com/path") == "example.com"

    def test_normalise_url_with_port(self):
        """normalise() preserves port in URLs."""
        assert normalise("https://example.com:8443/path") == "example.com:8443"

    def test_normalise_url_case_insensitive(self):
        """normalise() handles protocol in case-insensitive manner."""
        assert normalise("HTTPS://example.com") == "example.com"
        assert normalise("HtTpS://example.com") == "example.com"

    def test_normalise_plain_domain(self):
        """normalise() returns plain domain unchanged."""
        assert normalise("example.com") == "example.com"

    def test_normalise_domain_with_port(self):
        """normalise() preserves port in plain domain."""
        assert normalise("example.com:8080") == "example.com:8080"

    def test_normalise_strips_whitespace(self):
        """normalise() strips leading and trailing whitespace."""
        assert normalise("  example.com  ") == "example.com"
        assert normalise("  https://example.com  ") == "example.com"

    def test_normalise_strips_trailing_slashes(self):
        """normalise() removes trailing slashes from plain domains."""
        assert normalise("example.com/") == "example.com"
        assert normalise("example.com///") == "example.com"

    def test_normalise_ip_address(self):
        """normalise() handles IPv4 addresses."""
        assert normalise("192.168.1.1") == "192.168.1.1"

    def test_normalise_ip_with_trailing_slash(self):
        """normalise() removes trailing slashes from IPs."""
        assert normalise("192.168.1.1/") == "192.168.1.1"


# ═════════════════════════════════════════════════════════════════════════════
# TEST: validate()
# ═════════════════════════════════════════════════════════════════════════════

class TestValidate:
    """Test validate() function for target validation."""

    def test_validate_ipv4_valid(self):
        """validate() recognizes valid IPv4 addresses."""
        assert validate("192.168.1.1") == "ip"
        assert validate("127.0.0.1") == "ip"
        assert validate("255.255.255.255") == "ip"
        assert validate("10.0.0.1") == "ip"

    def test_validate_ipv4_invalid_octet(self):
        """validate() rejects IPv4 with out-of-range octets."""
        assert validate("256.168.1.1") is None
        assert validate("192.256.1.1") is None
        assert validate("192.168.256.1") is None
        assert validate("192.168.1.256") is None

    def test_validate_ipv4_incomplete(self):
        """validate() rejects incomplete IPv4 addresses."""
        assert validate("192.168.1") is None
        assert validate("192.168") is None
        assert validate("192") is None

    def test_validate_domain_valid(self):
        """validate() recognizes valid domains."""
        assert validate("example.com") == "domain"
        assert validate("sub.example.com") == "domain"
        assert validate("my-domain.co.uk") == "domain"
        assert validate("a.b") == "domain"

    def test_validate_domain_with_port(self):
        """validate() accepts domains with valid ports."""
        assert validate("example.com:8080") == "domain"
        assert validate("example.com:443") == "domain"
        assert validate("sub.example.com:3000") == "domain"

    def test_validate_domain_with_invalid_port(self):
        """validate() rejects domains with invalid ports."""
        assert validate("example.com:99999") is None
        assert validate("example.com:0") is None

    def test_validate_domain_invalid_format(self):
        """validate() rejects malformed domains."""
        assert validate("-example.com") is None
        assert validate("example-.com") is None
        assert validate("example..com") is None
        assert validate("example.c") is None
        assert validate(".com") is None

    def test_validate_domain_single_label(self):
        """validate() rejects single-label domains without TLD."""
        assert validate("localhost") is None
        assert validate("intranet") is None

    def test_validate_empty_string(self):
        """validate() rejects empty strings."""
        assert validate("") is None

    def test_validate_special_characters(self):
        """validate() rejects special characters."""
        assert validate("exam!ple.com") is None
        assert validate("example.com@") is None


# ═════════════════════════════════════════════════════════════════════════════
# TEST: sanitise()
# ═════════════════════════════════════════════════════════════════════════════

class TestSanitise:
    """Test sanitise() function for shell safety."""

    def test_sanitise_safe_input(self):
        """sanitise() accepts safe alphanumeric input."""
        assert sanitise("example.com") == "example.com"
        assert sanitise("192.168.1.1") == "192.168.1.1"
        assert sanitise("my-domain.co.uk") == "my-domain.co.uk"

    def test_sanitise_allows_colon(self):
        """sanitise() allows colons for host:port syntax."""
        assert sanitise("example.com:8080") == "example.com:8080"
        assert sanitise("192.168.1.1:443") == "192.168.1.1:443"

    def test_sanitise_rejects_semicolon(self):
        """sanitise() blocks semicolons (command separator)."""
        with pytest.raises(ValueError):
            sanitise("example.com;rm -rf /")

    def test_sanitise_rejects_ampersand(self):
        """sanitise() blocks ampersands (background execution)."""
        with pytest.raises(ValueError):
            sanitise("example.com&ls")

    def test_sanitise_rejects_pipe(self):
        """sanitise() blocks pipes (command chaining)."""
        with pytest.raises(ValueError):
            sanitise("example.com|cat")

    def test_sanitise_rejects_backtick(self):
        """sanitise() blocks backticks (command substitution)."""
        with pytest.raises(ValueError):
            sanitise("example.com`whoami`")

    def test_sanitise_rejects_dollar_sign(self):
        """sanitise() blocks dollar signs (variable expansion)."""
        with pytest.raises(ValueError):
            sanitise("example.com$PATH")

    def test_sanitise_rejects_angle_brackets(self):
        """sanitise() blocks angle brackets (redirection)."""
        with pytest.raises(ValueError):
            sanitise("example.com>file.txt")
        with pytest.raises(ValueError):
            sanitise("example.com<file.txt")

    def test_sanitise_rejects_parentheses(self):
        """sanitise() blocks parentheses (subshell execution)."""
        with pytest.raises(ValueError):
            sanitise("example.com(echo)")

    def test_sanitise_rejects_quotes(self):
        """sanitise() blocks quotes (escape sequences)."""
        with pytest.raises(ValueError):
            sanitise("example.com'")
        with pytest.raises(ValueError):
            sanitise('example.com"')

    def test_sanitise_rejects_backslash(self):
        """sanitise() blocks backslashes (escape character)."""
        with pytest.raises(ValueError):
            sanitise("example.com\\")

    def test_sanitise_rejects_curly_braces(self):
        """sanitise() blocks curly braces (brace expansion)."""
        with pytest.raises(ValueError):
            sanitise("example.com{1,2}")

    def test_sanitise_error_message_includes_input(self):
        """sanitise() includes dangerous input in error message."""
        with pytest.raises(ValueError) as excinfo:
            sanitise("example.com;rm -rf /")
        assert "Unsafe characters" in str(excinfo.value)


# ═════════════════════════════════════════════════════════════════════════════
# TEST: yes_no()
# ═════════════════════════════════════════════════════════════════════════════

class TestYesNo:
    """Test yes_no() function for interactive prompting."""

    @patch('builtins.input', return_value='y')
    def test_yes_no_single_y(self, mock_input):
        """yes_no() returns True for 'y'."""
        assert yes_no("Continue?") is True

    @patch('builtins.input', return_value='yes')
    def test_yes_no_word_yes(self, mock_input):
        """yes_no() returns True for 'yes'."""
        assert yes_no("Continue?") is True

    @patch('builtins.input', return_value='n')
    def test_yes_no_single_n(self, mock_input):
        """yes_no() returns False for 'n'."""
        assert yes_no("Continue?") is False

    @patch('builtins.input', return_value='no')
    def test_yes_no_word_no(self, mock_input):
        """yes_no() returns False for 'no'."""
        assert yes_no("Continue?") is False

    @patch('builtins.input', return_value='Y')
    def test_yes_no_uppercase(self, mock_input):
        """yes_no() is case-insensitive for yes."""
        assert yes_no("Continue?") is True

    @patch('builtins.input', return_value='YES')
    def test_yes_no_uppercase_yes(self, mock_input):
        """yes_no() is case-insensitive for YES."""
        assert yes_no("Continue?") is True

    @patch('builtins.input', return_value='N')
    def test_yes_no_uppercase_no(self, mock_input):
        """yes_no() is case-insensitive for no."""
        assert yes_no("Continue?") is False

    @patch('builtins.input', side_effect=['maybe', 'y'])
    def test_yes_no_invalid_then_valid(self, mock_input):
        """yes_no() retries on invalid input."""
        assert yes_no("Continue?") is True
        # Called twice: once for 'maybe', once for 'y'
        assert mock_input.call_count == 2

    @patch('builtins.input', side_effect=['', 'maybe', 'n'])
    def test_yes_no_multiple_retries(self, mock_input):
        """yes_no() retries multiple times until valid response."""
        assert yes_no("Continue?") is False
        assert mock_input.call_count == 3

    @patch('builtins.input', return_value='y')
    def test_yes_no_includes_prompt_text(self, mock_input):
        """yes_no() includes prompt text and (y/n) option."""
        yes_no("Do something")
        called_with = mock_input.call_args[0][0]
        assert "Do something" in called_with
        assert "(y/n)" in called_with


# ═════════════════════════════════════════════════════════════════════════════
# TEST: diff_findings()
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class MockFinding:
    """Mock Finding class for testing diff_findings()."""
    title: str
    severity: str = "INFO"


class TestDiffFindings:
    """Test diff_findings() function for comparing findings."""

    def test_diff_findings_file_not_exists(self):
        """diff_findings() returns empty dict when previous file doesn't exist."""
        result = diff_findings([], "/nonexistent/file.json")
        assert result == {}

    def test_diff_findings_no_findings(self):
        """diff_findings() handles empty findings list."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([], f)
            f.flush()
            try:
                result = diff_findings([], f.name)
                assert result == {}
            finally:
                os.unlink(f.name)

    def test_diff_findings_no_new_findings(self):
        """diff_findings() returns empty when all findings unchanged."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([{'title': 'Test Finding'}], f)
            f.flush()
            try:
                current = [MockFinding(title='Test Finding')]
                result = diff_findings(current, f.name)
                assert result.get('new') == []
                assert result.get('resolved') == []
                assert result.get('unchanged') == 1
            finally:
                os.unlink(f.name)

    def test_diff_findings_new_findings(self):
        """diff_findings() identifies new findings."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([{'title': 'Old Finding'}], f)
            f.flush()
            try:
                current = [
                    MockFinding(title='Old Finding'),
                    MockFinding(title='New Finding'),
                ]
                result = diff_findings(current, f.name)
                assert len(result.get('new', [])) == 1
                assert result['new'][0]['title'] == 'New Finding'
            finally:
                os.unlink(f.name)

    def test_diff_findings_resolved_findings(self):
        """diff_findings() identifies resolved findings."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([
                {'title': 'Old Finding'},
                {'title': 'Resolved Finding'},
            ], f)
            f.flush()
            try:
                current = [MockFinding(title='Old Finding')]
                result = diff_findings(current, f.name)
                assert 'Resolved Finding' in result.get('resolved', [])
            finally:
                os.unlink(f.name)

    def test_diff_findings_mixed_changes(self):
        """diff_findings() correctly identifies new, resolved, and unchanged."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([
                {'title': 'Unchanged'},
                {'title': 'Resolved'},
            ], f)
            f.flush()
            try:
                current = [
                    MockFinding(title='Unchanged'),
                    MockFinding(title='New'),
                ]
                result = diff_findings(current, f.name)
                assert len(result.get('new', [])) == 1
                assert result['new'][0]['title'] == 'New'
                assert 'Resolved' in result.get('resolved', [])
                assert result.get('unchanged') == 1
            finally:
                os.unlink(f.name)

    def test_diff_findings_corrupted_json(self):
        """diff_findings() returns empty dict on corrupted JSON."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            f.write("{invalid json]")
            f.flush()
            try:
                result = diff_findings([], f.name)
                assert result == {}
            finally:
                os.unlink(f.name)

    def test_diff_findings_empty_prev_file(self):
        """diff_findings() handles empty previous findings file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump([], f)
            f.flush()
            try:
                current = [MockFinding(title='New Finding')]
                result = diff_findings(current, f.name)
                assert len(result.get('new', [])) == 1
                assert result['new'][0]['title'] == 'New Finding'
                assert result.get('resolved') == []
                assert result.get('unchanged') == 0
            finally:
                os.unlink(f.name)
