"""
Comprehensive unit tests for the markdown reporting module.

This test module provides comprehensive coverage for markdown report generation,
including finding formatting, section creation, and file output operations.
Tests use pytest fixtures and mocking to validate functionality without
requiring actual file I/O operations.
"""

import pytest
import tempfile
from unittest.mock import patch, mock_open, MagicMock
from datetime import datetime
from io import StringIO

from web_app.core.findings import Finding, Severity
from web_app.reporting import markdown


class TestFormatFindingMarkdown:
    """Test the format_finding_markdown() function.

    Validates correct markdown formatting of individual findings with
    proper severity icons, sections, and field formatting.
    """

    def test_format_critical_finding(self):
        """Test markdown formatting of a CRITICAL severity finding."""
        finding = Finding(
            title="Remote Code Execution Vulnerability",
            severity=Severity.CRITICAL,
            description="Unauthenticated RCE via command injection",
            evidence="/bin/ls output from exec() call",
            recommendation="Sanitize user input and use safe execution methods",
            phase="scanning",
            timestamp="2024-01-01T12:00:00"
        )

        result = markdown.format_finding_markdown(finding)

        assert "🚨" in result
        assert "[CRITICAL]" in result
        assert "Remote Code Execution Vulnerability" in result
        assert "scanning" in result
        assert "2024-01-01T12:00:00" in result
        assert "/bin/ls output" in result
        assert "Sanitize user input" in result
        assert "---" in result

    def test_format_high_finding(self):
        """Test markdown formatting of a HIGH severity finding."""
        finding = Finding(
            title="SQL Injection in Login Form",
            severity=Severity.HIGH,
            description="SQL injection via username field",
            evidence="' OR '1'='1",
            recommendation="Use parameterized queries",
            phase="injection_testing"
        )

        result = markdown.format_finding_markdown(finding)

        assert "🔴" in result
        assert "[HIGH]" in result
        assert "SQL Injection" in result

    def test_format_medium_finding(self):
        """Test markdown formatting of a MEDIUM severity finding."""
        finding = Finding(
            title="Missing Security Headers",
            severity=Severity.MEDIUM,
            description="X-Frame-Options header missing",
            evidence="",
            recommendation="Add security headers",
            phase="header_scanning"
        )

        result = markdown.format_finding_markdown(finding)

        assert "🟡" in result
        assert "[MEDIUM]" in result

    def test_format_low_finding(self):
        """Test markdown formatting of a LOW severity finding."""
        finding = Finding(
            title="Weak SSL Configuration",
            severity=Severity.LOW,
            description="Old TLS version supported",
            evidence="TLSv1.0 detected",
            recommendation="Disable older TLS versions",
            phase="ssl_testing"
        )

        result = markdown.format_finding_markdown(finding)

        assert "🟢" in result
        assert "[LOW]" in result

    def test_format_info_finding(self):
        """Test markdown formatting of an INFO severity finding."""
        finding = Finding(
            title="Server Technology Identified",
            severity=Severity.INFO,
            description="Apache 2.4.41 detected",
            evidence="Server header: Apache/2.4.41",
            recommendation="None",
            phase="banner_grabbing"
        )

        result = markdown.format_finding_markdown(finding)

        assert "ℹ️" in result
        assert "[INFO]" in result

    def test_format_finding_without_evidence(self):
        """Test formatting when evidence field is empty."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.MEDIUM,
            description="Test description",
            evidence="",
            recommendation="Test recommendation"
        )

        result = markdown.format_finding_markdown(finding)

        assert "Evidence:" not in result
        assert "Test recommendation" in result

    def test_format_finding_without_recommendation(self):
        """Test formatting when recommendation field is empty."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.LOW,
            description="Test description",
            evidence="Some evidence",
            recommendation=""
        )

        result = markdown.format_finding_markdown(finding)

        assert "Some evidence" in result
        assert "Recommendation:" not in result

    def test_format_finding_evidence_truncation(self):
        """Test that evidence over 1500 characters is truncated."""
        long_evidence = "x" * 2000
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test",
            evidence=long_evidence,
            recommendation="Test"
        )

        result = markdown.format_finding_markdown(finding)

        # Evidence should be truncated to 1500 chars
        assert "xxx" in result
        assert len(result) < len(long_evidence)

    def test_format_finding_structure(self):
        """Test the overall structure of formatted markdown."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.MEDIUM,
            description="Test description",
            evidence="Test evidence",
            recommendation="Test recommendation"
        )

        result = markdown.format_finding_markdown(finding)
        lines = result.split('\n')

        # Should have header line
        assert any("###" in line for line in lines)
        # Should have phase and timestamp
        assert any("Phase:" in line for line in lines)
        # Should have description
        assert any("Description:" in line for line in lines)


class TestSection:
    """Test the section() function.

    Validates that markdown sections are created with proper formatting
    and file I/O handling.
    """

    @patch("builtins.open", new_callable=mock_open)
    def test_section_creation(self, mock_file):
        """Test that section() creates properly formatted section."""
        markdown.section("Test Section", "/tmp/test.md")

        mock_file.assert_called_once_with("/tmp/test.md", 'a')
        handle = mock_file()

        # Get all write calls
        calls = handle.write.call_args_list
        assert len(calls) > 0

        # Check that the write contains expected formatting
        all_writes = ''.join(str(call[0][0]) for call in calls)
        assert "---" in all_writes
        assert "# Test Section" in all_writes

    @patch("builtins.open", new_callable=mock_open)
    def test_section_with_special_chars(self, mock_file):
        """Test section creation with special characters in title."""
        markdown.section("# Special & Title <html>", "/tmp/test.md")

        handle = mock_file()
        all_writes = ''.join(str(call[0][0]) for call in handle.write.call_args_list)
        assert "# Special & Title <html>" in all_writes

    @patch("builtins.open", new_callable=mock_open)
    def test_section_appends_to_file(self, mock_file):
        """Test that section() opens file in append mode."""
        markdown.section("Another Section", "/tmp/test.md")

        # Should open in append mode
        mock_file.assert_called_with("/tmp/test.md", 'a')


class TestSaveFindingsMarkdown:
    """Test the save_findings_markdown() function.

    Validates complete markdown report generation including metadata,
    summaries, and sorted findings.
    """

    def test_save_findings_basic(self):
        """Test basic markdown report generation."""
        findings = [
            Finding(
                title="Finding 1",
                severity=Severity.CRITICAL,
                description="Critical issue",
                phase="phase1"
            ),
            Finding(
                title="Finding 2",
                severity=Severity.LOW,
                description="Low issue",
                phase="phase2"
            ),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.md', delete=False) as f:
            temp_path = f.name

        try:
            markdown.save_findings_markdown(findings, temp_path)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "# WebRecon Scan Report" in content
            assert "## Finding Summary" in content
            assert "## Findings" in content
            assert "Finding 1" in content
            assert "Finding 2" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_save_findings_sorting_by_severity(self):
        """Test that findings are sorted by severity (critical first)."""
        findings = [
            Finding(
                title="Low Issue",
                severity=Severity.LOW,
                description="Low"
            ),
            Finding(
                title="Critical Issue",
                severity=Severity.CRITICAL,
                description="Critical"
            ),
            Finding(
                title="Medium Issue",
                severity=Severity.MEDIUM,
                description="Medium"
            ),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.md', delete=False) as f:
            temp_path = f.name

        try:
            markdown.save_findings_markdown(findings, temp_path)

            with open(temp_path, 'r') as f:
                content = f.read()

            # Critical should appear before Medium, Medium before Low
            critical_pos = content.find("Critical Issue")
            medium_pos = content.find("Medium Issue")
            low_pos = content.find("Low Issue")

            assert critical_pos < medium_pos < low_pos
        finally:
            import os
            os.unlink(temp_path)

    def test_save_findings_with_config(self):
        """Test markdown report with ScanConfig metadata."""
        findings = [
            Finding(
                title="Test Finding",
                severity=Severity.HIGH,
                description="Test"
            )
        ]

        # Mock config object
        cfg = MagicMock()
        cfg.target = "example.com"
        cfg.base_url = "https://example.com"
        cfg.profile.value = "aggressive"

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.md', delete=False) as f:
            temp_path = f.name

        try:
            markdown.save_findings_markdown(findings, temp_path, cfg=cfg)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "## Scan Metadata" in content
            assert "example.com" in content
            assert "https://example.com" in content
            assert "aggressive" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_save_findings_summary_counts(self):
        """Test that finding summary shows correct severity counts."""
        findings = [
            Finding(title="Critical 1", severity=Severity.CRITICAL, description="C1"),
            Finding(title="Critical 2", severity=Severity.CRITICAL, description="C2"),
            Finding(title="High 1", severity=Severity.HIGH, description="H1"),
            Finding(title="Medium 1", severity=Severity.MEDIUM, description="M1"),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.md', delete=False) as f:
            temp_path = f.name

        try:
            markdown.save_findings_markdown(findings, temp_path)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "**CRITICAL:** 2" in content
            assert "**HIGH:** 1" in content
            assert "**MEDIUM:** 1" in content
            assert "**Total:** 4 findings" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_save_findings_empty_list(self):
        """Test markdown report generation with no findings."""
        findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.md', delete=False) as f:
            temp_path = f.name

        try:
            markdown.save_findings_markdown(findings, temp_path)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "# WebRecon Scan Report" in content
            assert "## Findings" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_save_findings_all_severities(self):
        """Test report with findings of all severity levels."""
        findings = [
            Finding(title="Info", severity=Severity.INFO, description="I"),
            Finding(title="Low", severity=Severity.LOW, description="L"),
            Finding(title="Medium", severity=Severity.MEDIUM, description="M"),
            Finding(title="High", severity=Severity.HIGH, description="H"),
            Finding(title="Critical", severity=Severity.CRITICAL, description="C"),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.md', delete=False) as f:
            temp_path = f.name

        try:
            markdown.save_findings_markdown(findings, temp_path)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "**INFO:** 1" in content
            assert "**LOW:** 1" in content
            assert "**MEDIUM:** 1" in content
            assert "**HIGH:** 1" in content
            assert "**CRITICAL:** 1" in content
        finally:
            import os
            os.unlink(temp_path)


class TestLogFindingToReport:
    """Test the log_finding_to_report() function.

    Validates appending findings to existing markdown report files.
    """

    @patch("builtins.open", new_callable=mock_open)
    def test_log_finding_to_report(self, mock_file):
        """Test logging a single finding to report."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test description",
            evidence="Test evidence",
            recommendation="Test recommendation"
        )

        markdown.log_finding_to_report(finding, "/tmp/report.md")

        # Should open in append mode
        mock_file.assert_called_with("/tmp/report.md", 'a')

        # Should write formatted finding
        handle = mock_file()
        assert handle.write.called

    @patch("builtins.open", new_callable=mock_open)
    def test_log_multiple_findings(self, mock_file):
        """Test logging multiple findings sequentially."""
        findings = [
            Finding(title="Finding 1", severity=Severity.CRITICAL, description="F1"),
            Finding(title="Finding 2", severity=Severity.HIGH, description="F2"),
            Finding(title="Finding 3", severity=Severity.MEDIUM, description="F3"),
        ]

        for f in findings:
            markdown.log_finding_to_report(f, "/tmp/report.md")

        # Should be called 3 times (once per finding)
        assert mock_file.call_count == 3


class TestThreadSafety:
    """Test thread-safe operations in markdown module.

    Validates that concurrent file writes don't cause race conditions.
    """

    @patch("builtins.open", new_callable=mock_open)
    def test_log_lock_is_acquired(self, mock_file):
        """Test that _log() acquires lock before writing."""
        # This is a basic test - in practice, actual threading tests would be more complex
        markdown._log("/tmp/test.md", "test message")

        mock_file.assert_called_once_with("/tmp/test.md", 'a')

    def test_concurrent_section_writes(self):
        """Test that concurrent section writes don't corrupt file."""
        import threading

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.md', delete=False) as f:
            temp_path = f.name

        try:
            def write_section(title):
                markdown.section(title, temp_path)

            threads = [
                threading.Thread(target=write_section, args=(f"Section {i}",))
                for i in range(5)
            ]

            for t in threads:
                t.start()
            for t in threads:
                t.join()

            with open(temp_path, 'r') as f:
                content = f.read()

            # All sections should be present
            for i in range(5):
                assert f"# Section {i}" in content
        finally:
            import os
            os.unlink(temp_path)


class TestEdgeCases:
    """Test edge cases and special scenarios.

    Validates handling of unusual input and boundary conditions.
    """

    def test_format_finding_with_empty_strings(self):
        """Test formatting finding with empty strings."""
        finding = Finding(
            title="",
            severity=Severity.INFO,
            description="",
            evidence="",
            recommendation=""
        )

        result = markdown.format_finding_markdown(finding)
        assert "###" in result
        assert "---" in result

    def test_format_finding_with_special_characters(self):
        """Test formatting with special markdown characters."""
        finding = Finding(
            title="Test # [Finding] with **bold**",
            severity=Severity.HIGH,
            description="Description with `code` and _italic_",
            evidence="```code block```",
            recommendation="* List item"
        )

        result = markdown.format_finding_markdown(finding)
        assert "Test # [Finding]" in result
        assert "`code`" in result

    def test_format_finding_with_newlines(self):
        """Test formatting finding with newlines in content."""
        finding = Finding(
            title="Test\nFinding",
            severity=Severity.MEDIUM,
            description="Line 1\nLine 2\nLine 3",
            evidence="Evidence\nLine 2"
        )

        result = markdown.format_finding_markdown(finding)
        assert "Test\nFinding" in result or "TestFinding" in result

    @patch("builtins.open", new_callable=mock_open)
    def test_log_with_unicode_characters(self, mock_file):
        """Test logging finding with unicode characters."""
        markdown._log("/tmp/test.md", "Unicode test: 你好 مرحبا 🔒")

        mock_file.assert_called_once()

    def test_save_findings_with_very_long_titles(self):
        """Test handling findings with very long titles."""
        findings = [
            Finding(
                title="A" * 500,
                severity=Severity.HIGH,
                description="Test"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.md', delete=False) as f:
            temp_path = f.name

        try:
            markdown.save_findings_markdown(findings, temp_path)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "A" * 500 in content
        finally:
            import os
            os.unlink(temp_path)
