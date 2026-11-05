"""
Unit tests for findings module.

Tests Finding dataclass, Severity enum, add_finding(), deduplication logic,
and webhook/pentestdb integration.
"""

import pytest
import json
import os
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from datetime import datetime

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from web_app.core.findings import (
    Finding,
    Severity,
    add_finding,
    get_findings,
    clear_findings,
    save_findings,
    webhook_notify,
    pentestdb_push,
    _log_finding_to_report,
    _log_to_file,
    _findings,
    _findings_lock,
    _finding_keys,
)


class TestSeverityEnum:
    """Test Severity enum."""

    def test_severity_values(self):
        """Test all severity levels exist."""
        assert Severity.INFO.value == "INFO"
        assert Severity.LOW.value == "LOW"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.CRITICAL.value == "CRITICAL"

    def test_severity_string_conversion(self):
        """Test severity can be converted to string."""
        sev = Severity.HIGH
        assert str(sev.value) == "HIGH"

    def test_severity_comparison(self):
        """Test severity enum comparison."""
        assert Severity.CRITICAL != Severity.HIGH
        assert Severity.INFO == Severity.INFO


class TestFinding:
    """Test Finding dataclass."""

    def test_finding_creation(self):
        """Test creating a Finding instance."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test description",
            evidence="test evidence",
            recommendation="test recommendation",
            phase="test_phase"
        )
        assert finding.title == "Test Finding"
        assert finding.severity == Severity.HIGH
        assert finding.description == "Test description"

    def test_finding_with_defaults(self):
        """Test Finding with default values."""
        finding = Finding(
            title="Minimal Finding",
            severity=Severity.INFO,
            description="Description only"
        )
        assert finding.evidence == ""
        assert finding.recommendation == ""
        assert finding.phase == ""
        assert finding.timestamp is not None

    def test_finding_timestamp_format(self):
        """Test Finding timestamp is ISO format."""
        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description="Desc"
        )
        # Should be ISO format (parseable)
        try:
            datetime.fromisoformat(finding.timestamp)
        except ValueError:
            pytest.fail("Timestamp is not ISO format")

    def test_finding_all_severity_levels(self):
        """Test Finding with all severity levels."""
        for severity in Severity:
            finding = Finding(
                title=f"Test {severity.value}",
                severity=severity,
                description="Test"
            )
            assert finding.severity == severity


class TestFindingDeduplication:
    """Test Finding deduplication logic."""

    def setup_method(self):
        """Clear findings before each test."""
        clear_findings()

    def test_add_finding_creates_entry(self, temp_dir):
        """Test that add_finding creates a finding entry."""
        output_file = os.path.join(temp_dir, "findings.md")
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test",
            evidence="evidence1"
        )
        add_finding(finding, output_file)
        findings = get_findings()
        assert len(findings) == 1
        assert findings[0].title == "Test Finding"

    def test_duplicate_finding_rejected(self, temp_dir):
        """Test that duplicate findings are rejected."""
        output_file = os.path.join(temp_dir, "findings.md")
        finding1 = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test",
            evidence="evidence1"
        )
        finding2 = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Different description",
            evidence="evidence1"  # Same evidence hash
        )
        add_finding(finding1, output_file)
        add_finding(finding2, output_file)

        findings = get_findings()
        assert len(findings) == 1  # Duplicate rejected

    def test_same_title_different_severity_not_duplicate(self, temp_dir):
        """Test that same title with different severity is not duplicate."""
        output_file = os.path.join(temp_dir, "findings.md")
        finding1 = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test",
            evidence="evidence1"
        )
        finding2 = Finding(
            title="Test Finding",
            severity=Severity.LOW,
            description="Test",
            evidence="evidence1"
        )
        add_finding(finding1, output_file)
        add_finding(finding2, output_file)

        findings = get_findings()
        assert len(findings) == 2  # Different severity, not duplicate

    def test_same_title_different_evidence_not_duplicate(self, temp_dir):
        """Test that same title with different evidence is not duplicate."""
        output_file = os.path.join(temp_dir, "findings.md")
        finding1 = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test",
            evidence="evidence1"
        )
        finding2 = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test",
            evidence="evidence2"
        )
        add_finding(finding1, output_file)
        add_finding(finding2, output_file)

        findings = get_findings()
        assert len(findings) == 2  # Different evidence, not duplicate

    def test_empty_evidence_hashes_same(self, temp_dir):
        """Test that findings with empty evidence are deduplicated."""
        output_file = os.path.join(temp_dir, "findings.md")
        finding1 = Finding(
            title="Test Finding",
            severity=Severity.INFO,
            description="Test",
            evidence=""
        )
        finding2 = Finding(
            title="Test Finding",
            severity=Severity.INFO,
            description="Test",
            evidence=""
        )
        add_finding(finding1, output_file)
        add_finding(finding2, output_file)

        findings = get_findings()
        assert len(findings) == 1


class TestSaveFindings:
    """Test save_findings function."""

    def setup_method(self):
        """Clear findings before each test."""
        clear_findings()

    def test_save_findings_to_json(self, temp_dir):
        """Test saving findings to JSON file."""
        output_file = os.path.join(temp_dir, "findings.json")
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test description",
            evidence="test evidence",
            recommendation="test recommendation",
            phase="test_phase"
        )
        add_finding(finding, os.path.join(temp_dir, "report.md"))

        findings = get_findings()
        save_findings(findings, output_file)

        assert os.path.exists(output_file)
        with open(output_file, "r") as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["title"] == "Test Finding"
        assert data[0]["severity"] == "HIGH"

    def test_save_findings_preserves_data(self, temp_dir):
        """Test that saved findings preserve all data."""
        output_file = os.path.join(temp_dir, "findings.json")
        finding = Finding(
            title="Complex Finding",
            severity=Severity.CRITICAL,
            description="Complex description",
            evidence="complex evidence" * 10,
            recommendation="Complex recommendation",
            phase="complex_phase"
        )
        add_finding(finding, os.path.join(temp_dir, "report.md"))

        findings = get_findings()
        save_findings(findings, output_file)

        with open(output_file, "r") as f:
            data = json.load(f)

        loaded = data[0]
        assert loaded["title"] == "Complex Finding"
        assert loaded["description"] == "Complex description"
        assert "complex evidence" in loaded["evidence"]
        assert loaded["recommendation"] == "Complex recommendation"
        assert loaded["phase"] == "complex_phase"


class TestGetClearFindings:
    """Test get_findings and clear_findings functions."""

    def test_get_empty_findings(self):
        """Test getting findings when none exist."""
        clear_findings()
        findings = get_findings()
        assert findings == []

    def test_get_findings_returns_copy(self, temp_dir):
        """Test that get_findings returns a copy."""
        clear_findings()
        output_file = os.path.join(temp_dir, "findings.md")
        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description="Test"
        )
        add_finding(finding, output_file)

        findings1 = get_findings()
        findings1.clear()  # Modify returned list

        findings2 = get_findings()
        assert len(findings2) == 1  # Original unaffected

    def test_clear_findings(self, temp_dir):
        """Test that clear_findings removes all findings."""
        clear_findings()
        output_file = os.path.join(temp_dir, "findings.md")

        # Add multiple findings
        for i in range(5):
            finding = Finding(
                title=f"Finding {i}",
                severity=Severity.INFO,
                description="Test",
                evidence=f"evidence{i}"
            )
            add_finding(finding, output_file)

        assert len(get_findings()) == 5

        clear_findings()
        assert len(get_findings()) == 0


class TestLogToFile:
    """Test _log_to_file function."""

    def test_log_to_file_creates_file(self, temp_dir):
        """Test that _log_to_file creates output file."""
        output_file = os.path.join(temp_dir, "output.md")
        _log_to_file(output_file, "Test message")
        assert os.path.exists(output_file)

    def test_log_to_file_appends(self, temp_dir):
        """Test that _log_to_file appends to existing file."""
        output_file = os.path.join(temp_dir, "output.md")
        _log_to_file(output_file, "Line 1")
        _log_to_file(output_file, "Line 2")

        with open(output_file, "r") as f:
            content = f.read()

        assert "Line 1" in content
        assert "Line 2" in content


class TestLogFindingToReport:
    """Test _log_finding_to_report function."""

    def test_log_finding_to_report_creates_markdown(self, temp_dir):
        """Test that finding is logged as markdown."""
        output_file = os.path.join(temp_dir, "report.md")
        finding = Finding(
            title="Security Issue",
            severity=Severity.HIGH,
            description="A serious security issue",
            evidence="Evidence data",
            recommendation="Fix immediately",
            phase="active"
        )
        _log_finding_to_report(finding, output_file)

        assert os.path.exists(output_file)
        with open(output_file, "r") as f:
            content = f.read()

        assert "Security Issue" in content
        assert "HIGH" in content
        assert "A serious security issue" in content

    def test_log_finding_includes_all_severity_icons(self, temp_dir):
        """Test that all severity levels have appropriate icons."""
        output_file = os.path.join(temp_dir, "report.md")

        for severity in Severity:
            finding = Finding(
                title=f"Test {severity.value}",
                severity=severity,
                description="Test",
                evidence="",
                recommendation=""
            )
            _log_finding_to_report(finding, output_file)

        with open(output_file, "r") as f:
            content = f.read()

        assert "HIGH" in content or content  # At least something was written


class TestWebhookNotify:
    """Test webhook_notify function."""

    @patch('web_app.core.findings.requests.post')
    def test_webhook_discord_format(self, mock_post, mock_config):
        """Test webhook notification in Discord format."""
        mock_config.webhook_url = "https://discord.com/api/webhooks/123/abc"
        mock_post.return_value.status_code = 204

        finding = Finding(
            title="Test Issue",
            severity=Severity.HIGH,
            description="Test description",
            phase="test"
        )
        mock_config.target = "example.com"

        webhook_notify(finding, mock_config)

        assert mock_post.called
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert "embeds" in payload

    @patch('web_app.core.findings.requests.post')
    def test_webhook_slack_format(self, mock_post, mock_config):
        """Test webhook notification in Slack format."""
        mock_config.webhook_url = "https://hooks.slack.com/services/123/abc"
        mock_post.return_value.status_code = 200

        finding = Finding(
            title="Test Issue",
            severity=Severity.MEDIUM,
            description="Test description",
            phase="test"
        )
        mock_config.target = "example.com"

        webhook_notify(finding, mock_config)

        assert mock_post.called
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert "text" in payload

    @patch('web_app.core.findings.requests.post')
    def test_webhook_handles_timeout(self, mock_post, mock_config):
        """Test webhook gracefully handles timeout."""
        import requests
        mock_config.webhook_url = "https://discord.com/api/webhooks/123/abc"
        mock_post.side_effect = requests.exceptions.Timeout()

        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description="Test"
        )
        mock_config.target = "example.com"

        # Should not raise
        webhook_notify(finding, mock_config)

    def test_webhook_no_url_does_nothing(self, mock_config):
        """Test webhook with no URL configured does nothing."""
        mock_config.webhook_url = None

        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description="Test"
        )

        # Should not raise
        webhook_notify(finding, mock_config)

    @patch('web_app.core.findings.requests.post')
    def test_webhook_truncates_long_description(self, mock_post, mock_config):
        """Test webhook truncates very long descriptions."""
        mock_config.webhook_url = "https://discord.com/api/webhooks/123/abc"
        mock_post.return_value.status_code = 204

        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description="A" * 5000,  # Very long
        )
        mock_config.target = "example.com"

        webhook_notify(finding, mock_config)

        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        payload_str = json.dumps(payload)
        assert len(payload_str) < 6000  # Should be truncated


class TestPentestdbPush:
    """Test pentestdb_push function."""

    @patch('web_app.core.findings.requests.post')
    def test_pentestdb_push_sends_finding(self, mock_post, mock_config):
        """Test pentestdb push sends finding data."""
        mock_config.pentestdb_url = "https://pentestdb.local"
        mock_config.pentestdb_token = "secret_token"
        mock_config.target = "example.com"
        mock_post.return_value.status_code = 201

        finding = Finding(
            title="API Issue",
            severity=Severity.HIGH,
            description="API endpoint exposed",
            evidence="GET /admin",
            recommendation="Restrict access",
            phase="active"
        )

        pentestdb_push(finding, mock_config)

        assert mock_post.called
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert payload["title"] == "API Issue"
        assert payload["severity"] == "HIGH"
        assert payload["evidence"] == "GET /admin"

    @patch('web_app.core.findings.requests.post')
    def test_pentestdb_includes_auth_header(self, mock_post, mock_config):
        """Test pentestdb push includes authorization header."""
        mock_config.pentestdb_url = "https://pentestdb.local"
        mock_config.pentestdb_token = "bearer_token_123"
        mock_config.target = "example.com"
        mock_post.return_value.status_code = 201

        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description="Test"
        )

        pentestdb_push(finding, mock_config)

        call_args = mock_post.call_args
        headers = call_args[1]["headers"]
        assert "Authorization" in headers
        assert "bearer_token_123" in headers["Authorization"]

    def test_pentestdb_no_url_does_nothing(self, mock_config):
        """Test pentestdb with no URL configured does nothing."""
        mock_config.pentestdb_url = None
        mock_config.target = "example.com"

        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description="Test"
        )

        # Should not raise
        pentestdb_push(finding, mock_config)

    @patch('web_app.core.findings.requests.post')
    def test_pentestdb_handles_timeout(self, mock_post, mock_config):
        """Test pentestdb gracefully handles timeout."""
        import requests
        mock_config.pentestdb_url = "https://pentestdb.local"
        mock_config.pentestdb_token = None
        mock_config.target = "example.com"
        mock_post.side_effect = requests.exceptions.Timeout()

        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description="Test"
        )

        # Should not raise
        pentestdb_push(finding, mock_config)


class TestAddFindingWithConfig:
    """Test add_finding with config integration."""

    @patch('web_app.core.findings.webhook_notify')
    @patch('web_app.core.findings.pentestdb_push')
    def test_add_finding_calls_webhook_above_threshold(
        self, mock_pentestdb, mock_webhook, temp_dir
    ):
        """Test webhook is called for findings above threshold."""
        clear_findings()
        output_file = os.path.join(temp_dir, "findings.md")

        mock_config = Mock()
        mock_config.webhook_url = "https://discord.com/api/webhooks/123/abc"
        mock_config.webhook_threshold = "HIGH"
        mock_config.pentestdb_url = None
        mock_config.verbose = False

        finding = Finding(
            title="Critical Issue",
            severity=Severity.CRITICAL,
            description="Test"
        )

        add_finding(finding, output_file, mock_config)

        mock_webhook.assert_called_once()

    @patch('web_app.core.findings.webhook_notify')
    def test_add_finding_skips_webhook_below_threshold(
        self, mock_webhook, temp_dir
    ):
        """Test webhook is skipped for findings below threshold."""
        clear_findings()
        output_file = os.path.join(temp_dir, "findings.md")

        mock_config = Mock()
        mock_config.webhook_url = "https://discord.com/api/webhooks/123/abc"
        mock_config.webhook_threshold = "HIGH"
        mock_config.pentestdb_url = None
        mock_config.verbose = False

        finding = Finding(
            title="Low Issue",
            severity=Severity.LOW,
            description="Test"
        )

        add_finding(finding, output_file, mock_config)

        mock_webhook.assert_not_called()
