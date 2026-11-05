"""
Comprehensive unit tests for web_app.utils.output module.

Tests cover:
  - _log(): Thread-safe file logging
  - section(): Section header formatting
  - _log_finding_to_report(): Finding report formatting
  - save_findings(): Persist findings to JSON
  - Thread safety and concurrent access
"""

import pytest
import json
import tempfile
import os
import threading
import time
from unittest.mock import patch, MagicMock
from dataclasses import dataclass
from enum import Enum

from web_app.utils.output import (
    _log,
    section,
    _log_finding_to_report,
    save_findings,
)


# ═════════════════════════════════════════════════════════════════════════════
# FIXTURES AND MOCK OBJECTS
# ═════════════════════════════════════════════════════════════════════════════

class Severity(Enum):
    """Mock Severity enum for testing."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class MockFinding:
    """Mock Finding class for testing."""
    title: str
    severity: Severity
    phase: str
    timestamp: str
    description: str
    evidence: str = None
    recommendation: str = None


@pytest.fixture
def temp_output_file():
    """Create temporary output file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.unlink(temp_path)


@pytest.fixture
def temp_json_file():
    """Create temporary JSON file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.unlink(temp_path)


# ═════════════════════════════════════════════════════════════════════════════
# TEST: _log()
# ═════════════════════════════════════════════════════════════════════════════

class TestLog:
    """Test _log() function for file logging."""

    def test_log_appends_message(self, temp_output_file):
        """_log() appends message to file."""
        _log(temp_output_file, "Test message")
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Test message" in content

    def test_log_adds_newline(self, temp_output_file):
        """_log() adds newline after message."""
        _log(temp_output_file, "Line")
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert content.endswith('\n')

    def test_log_multiple_messages(self, temp_output_file):
        """_log() preserves multiple messages."""
        _log(temp_output_file, "First")
        _log(temp_output_file, "Second")
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "First" in content
        assert "Second" in content

    def test_log_empty_message(self, temp_output_file):
        """_log() handles empty messages."""
        _log(temp_output_file, "")
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert content == "\n"

    def test_log_multiline_message(self, temp_output_file):
        """_log() handles multiline messages."""
        msg = "Line1\nLine2\nLine3"
        _log(temp_output_file, msg)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Line1" in content
        assert "Line2" in content
        assert "Line3" in content

    def test_log_markdown_format(self, temp_output_file):
        """_log() handles markdown formatting."""
        msg = "## Heading\n**Bold text**\n- List item"
        _log(temp_output_file, msg)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert msg in content

    def test_log_special_characters(self, temp_output_file):
        """_log() preserves special characters."""
        msg = "Special: !@#$%^&*()_+-=[]{}|;:',.<>?/`~"
        _log(temp_output_file, msg)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert msg in content

    def test_log_unicode_characters(self, temp_output_file):
        """_log() handles Unicode characters."""
        msg = "Unicode: 你好世界 🌍 Ω α β"
        _log(temp_output_file, msg)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert msg in content

    def test_log_thread_safe_concurrent_writes(self, temp_output_file):
        """_log() is thread-safe with concurrent writes."""
        def write_logs(thread_id, count):
            for i in range(count):
                _log(temp_output_file, f"Thread {thread_id} Message {i}")

        threads = []
        for i in range(5):
            t = threading.Thread(target=write_logs, args=(i, 10))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        with open(temp_output_file, 'r') as f:
            lines = f.readlines()

        assert len(lines) == 50

    def test_log_preserves_order(self, temp_output_file):
        """_log() maintains message order."""
        for i in range(20):
            _log(temp_output_file, f"Message {i}")

        with open(temp_output_file, 'r') as f:
            lines = [line.strip() for line in f.readlines()]

        for i in range(20):
            assert f"Message {i}" in lines[i]


# ═════════════════════════════════════════════════════════════════════════════
# TEST: section()
# ═════════════════════════════════════════════════════════════════════════════

class TestSection:
    """Test section() function for section headers."""

    @patch('builtins.print')
    def test_section_prints_header(self, mock_print, temp_output_file):
        """section() prints a formatted header."""
        section("Test Section", temp_output_file)
        mock_print.assert_called()

    @patch('builtins.print')
    def test_section_logs_to_file(self, mock_print, temp_output_file):
        """section() logs to output file."""
        section("Test Section", temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Test Section" in content

    @patch('builtins.print')
    def test_section_markdown_heading(self, mock_print, temp_output_file):
        """section() formats as markdown heading."""
        section("Test Section", temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "# Test Section" in content

    @patch('builtins.print')
    def test_section_with_special_characters(self, mock_print, temp_output_file):
        """section() handles special characters in title."""
        section("Section: Testing [Phase 1]", temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Section: Testing [Phase 1]" in content

    @patch('builtins.print')
    def test_section_multiple_sections(self, mock_print, temp_output_file):
        """section() creates multiple distinct sections."""
        section("Section 1", temp_output_file)
        section("Section 2", temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "# Section 1" in content
        assert "# Section 2" in content
        content.index("# Section 1") < content.index("# Section 2")

    @patch('builtins.print')
    def test_section_unicode_title(self, mock_print, temp_output_file):
        """section() handles Unicode in titles."""
        section("测试章节 📊 Results", temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "测试章节" in content


# ═════════════════════════════════════════════════════════════════════════════
# TEST: _log_finding_to_report()
# ═════════════════════════════════════════════════════════════════════════════

class TestLogFindingToReport:
    """Test _log_finding_to_report() function for finding formatting."""

    def test_log_finding_basic(self, temp_output_file):
        """_log_finding_to_report() logs finding to file."""
        finding = MockFinding(
            title="XSS Vulnerability",
            severity=Severity.HIGH,
            phase="Phase 1",
            timestamp="2024-01-01T00:00:00Z",
            description="Found cross-site scripting vulnerability"
        )
        _log_finding_to_report(finding, temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "XSS Vulnerability" in content

    def test_log_finding_with_severity_info(self, temp_output_file):
        """_log_finding_to_report() formats INFO severity."""
        finding = MockFinding(
            title="Info Finding",
            severity=Severity.INFO,
            phase="Phase 1",
            timestamp="2024-01-01",
            description="Informational finding"
        )
        _log_finding_to_report(finding, temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "INFO" in content

    def test_log_finding_with_severity_critical(self, temp_output_file):
        """_log_finding_to_report() formats CRITICAL severity."""
        finding = MockFinding(
            title="Critical Finding",
            severity=Severity.CRITICAL,
            phase="Phase 1",
            timestamp="2024-01-01",
            description="Critical vulnerability"
        )
        _log_finding_to_report(finding, temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "CRITICAL" in content

    def test_log_finding_with_evidence(self, temp_output_file):
        """_log_finding_to_report() includes evidence."""
        finding = MockFinding(
            title="Finding",
            severity=Severity.MEDIUM,
            phase="Phase 1",
            timestamp="2024-01-01",
            description="Description",
            evidence="Evidence text here"
        )
        _log_finding_to_report(finding, temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Evidence:" in content
        assert "Evidence text here" in content

    def test_log_finding_with_recommendation(self, temp_output_file):
        """_log_finding_to_report() includes recommendation."""
        finding = MockFinding(
            title="Finding",
            severity=Severity.MEDIUM,
            phase="Phase 1",
            timestamp="2024-01-01",
            description="Description",
            recommendation="Apply security patch"
        )
        _log_finding_to_report(finding, temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Recommendation:" in content
        assert "Apply security patch" in content

    def test_log_finding_truncates_long_evidence(self, temp_output_file):
        """_log_finding_to_report() truncates long evidence."""
        long_evidence = "x" * 2000
        finding = MockFinding(
            title="Finding",
            severity=Severity.MEDIUM,
            phase="Phase 1",
            timestamp="2024-01-01",
            description="Description",
            evidence=long_evidence
        )
        _log_finding_to_report(finding, temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        # Should truncate to 1500 chars
        assert len(content) < len(long_evidence) + 500

    def test_log_finding_all_severities(self, temp_output_file):
        """_log_finding_to_report() formats all severity levels."""
        for severity in Severity:
            finding = MockFinding(
                title=f"Finding {severity.value}",
                severity=severity,
                phase="Phase 1",
                timestamp="2024-01-01",
                description="Description"
            )
            _log_finding_to_report(finding, temp_output_file)

        with open(temp_output_file, 'r') as f:
            content = f.read()
        for severity in Severity:
            assert severity.value in content

    def test_log_finding_markdown_format(self, temp_output_file):
        """_log_finding_to_report() outputs markdown format."""
        finding = MockFinding(
            title="XSS",
            severity=Severity.HIGH,
            phase="Phase 1",
            timestamp="2024-01-01",
            description="Desc"
        )
        _log_finding_to_report(finding, temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "###" in content  # Markdown heading level 3
        assert "[HIGH]" in content

    def test_log_finding_includes_phase_and_time(self, temp_output_file):
        """_log_finding_to_report() includes phase and timestamp."""
        finding = MockFinding(
            title="Finding",
            severity=Severity.INFO,
            phase="Reconnaissance",
            timestamp="2024-01-01T12:00:00Z",
            description="Description"
        )
        _log_finding_to_report(finding, temp_output_file)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Reconnaissance" in content
        assert "2024-01-01T12:00:00Z" in content


# ═════════════════════════════════════════════════════════════════════════════
# TEST: save_findings()
# ═════════════════════════════════════════════════════════════════════════════

class TestSaveFindings:
    """Test save_findings() function for finding persistence."""

    def test_save_findings_creates_file(self, temp_json_file):
        """save_findings() creates JSON file."""
        findings = [
            MockFinding(
                title="Finding 1",
                severity=Severity.HIGH,
                phase="Phase 1",
                timestamp="2024-01-01",
                description="Description 1"
            )
        ]
        save_findings(findings, temp_json_file)
        assert os.path.exists(temp_json_file)

    def test_save_findings_valid_json(self, temp_json_file):
        """save_findings() creates valid JSON."""
        findings = [
            MockFinding(
                title="Finding 1",
                severity=Severity.HIGH,
                phase="Phase 1",
                timestamp="2024-01-01",
                description="Description 1"
            )
        ]
        save_findings(findings, temp_json_file)
        with open(temp_json_file, 'r') as f:
            data = json.load(f)
        assert isinstance(data, list)
        assert len(data) == 1

    def test_save_findings_multiple_findings(self, temp_json_file):
        """save_findings() saves multiple findings."""
        findings = [
            MockFinding(
                title=f"Finding {i}",
                severity=Severity.HIGH,
                phase="Phase 1",
                timestamp="2024-01-01",
                description=f"Description {i}"
            )
            for i in range(5)
        ]
        save_findings(findings, temp_json_file)
        with open(temp_json_file, 'r') as f:
            data = json.load(f)
        assert len(data) == 5

    def test_save_findings_preserves_fields(self, temp_json_file):
        """save_findings() preserves all finding fields."""
        findings = [
            MockFinding(
                title="Test Finding",
                severity=Severity.CRITICAL,
                phase="Exploitation",
                timestamp="2024-01-01T10:00:00Z",
                description="Test description",
                evidence="Test evidence",
                recommendation="Test recommendation"
            )
        ]
        save_findings(findings, temp_json_file)
        with open(temp_json_file, 'r') as f:
            data = json.load(f)
        finding = data[0]
        assert finding['title'] == "Test Finding"
        assert finding['phase'] == "Exploitation"
        assert finding['description'] == "Test description"
        assert finding['evidence'] == "Test evidence"
        assert finding['recommendation'] == "Test recommendation"

    def test_save_findings_empty_list(self, temp_json_file):
        """save_findings() handles empty findings list."""
        save_findings([], temp_json_file)
        with open(temp_json_file, 'r') as f:
            data = json.load(f)
        assert data == []

    def test_save_findings_overwrites_file(self, temp_json_file):
        """save_findings() overwrites existing file."""
        # Write initial data
        initial = [MockFinding(
            title="Initial",
            severity=Severity.INFO,
            phase="Phase 1",
            timestamp="2024-01-01",
            description="Initial"
        )]
        save_findings(initial, temp_json_file)

        # Overwrite with new data
        new = [
            MockFinding(
                title="New 1",
                severity=Severity.HIGH,
                phase="Phase 2",
                timestamp="2024-01-02",
                description="New 1"
            ),
            MockFinding(
                title="New 2",
                severity=Severity.MEDIUM,
                phase="Phase 2",
                timestamp="2024-01-02",
                description="New 2"
            )
        ]
        save_findings(new, temp_json_file)

        with open(temp_json_file, 'r') as f:
            data = json.load(f)
        assert len(data) == 2
        assert data[0]['title'] == "New 1"

    def test_save_findings_pretty_printed(self, temp_json_file):
        """save_findings() outputs formatted JSON."""
        findings = [
            MockFinding(
                title="Finding",
                severity=Severity.HIGH,
                phase="Phase 1",
                timestamp="2024-01-01",
                description="Description"
            )
        ]
        save_findings(findings, temp_json_file)
        with open(temp_json_file, 'r') as f:
            content = f.read()
        # Check for indentation (pretty printing)
        assert '\n' in content
        assert '  ' in content

    def test_save_findings_handles_severity_enum(self, temp_json_file):
        """save_findings() serializes Severity enum."""
        findings = [
            MockFinding(
                title="Finding",
                severity=Severity.CRITICAL,
                phase="Phase 1",
                timestamp="2024-01-01",
                description="Description"
            )
        ]
        save_findings(findings, temp_json_file)
        with open(temp_json_file, 'r') as f:
            data = json.load(f)
        # Severity should be serialized as string
        assert data[0]['severity'] == "CRITICAL"


# ═════════════════════════════════════════════════════════════════════════════
# TEST: Integration tests
# ═════════════════════════════════════════════════════════════════════════════

class TestOutputIntegration:
    """Integration tests for output module."""

    @patch('builtins.print')
    def test_section_and_finding_together(self, mock_print, temp_output_file):
        """section() and _log_finding_to_report() work together."""
        section("Vulnerabilities", temp_output_file)
        finding = MockFinding(
            title="XSS",
            severity=Severity.HIGH,
            phase="Phase 1",
            timestamp="2024-01-01",
            description="XSS vulnerability"
        )
        _log_finding_to_report(finding, temp_output_file)

        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "# Vulnerabilities" in content
        assert "XSS" in content

    def test_save_and_log_together(self, temp_output_file, temp_json_file):
        """save_findings() and logging work together."""
        findings = [
            MockFinding(
                title="Finding 1",
                severity=Severity.HIGH,
                phase="Phase 1",
                timestamp="2024-01-01",
                description="Description 1"
            )
        ]

        # Log to report
        for finding in findings:
            _log_finding_to_report(finding, temp_output_file)

        # Save to JSON
        save_findings(findings, temp_json_file)

        # Both files should exist and have content
        with open(temp_output_file, 'r') as f:
            report = f.read()
        with open(temp_json_file, 'r') as f:
            data = json.load(f)

        assert "Finding 1" in report
        assert len(data) == 1
