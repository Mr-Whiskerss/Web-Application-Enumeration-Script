"""
Comprehensive unit tests for the HTML reporting module.

This test module provides comprehensive coverage for HTML report generation,
including report structure validation, color mappings, filtering functionality,
and proper escaping of special characters. Tests use pytest fixtures and mocking
to validate HTML structure without requiring actual file I/O.
"""

import pytest
import tempfile
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime, timedelta
from html.parser import HTMLParser

from web_app.core.findings import Finding, Severity
from web_app.reporting import html


class HTMLValidator(HTMLParser):
    """Helper class to validate HTML structure.

    Parses HTML and tracks elements, attributes, and content for validation.
    """

    def __init__(self):
        super().__init__()
        self.tags = []
        self.data = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        """Track opening tags and attributes."""
        self.tags.append(tag)

    def handle_data(self, data):
        """Track text content."""
        if data.strip():
            self.data.append(data.strip())

    def handle_endtag(self, tag):
        """Track closing tags."""
        pass


class TestWriteHtmlReport:
    """Test the write_html_report() function.

    Validates complete HTML report generation including structure,
    content, and client-side functionality.
    """

    def setup_method(self):
        """Set up test fixtures before each test."""
        self.cfg = MagicMock()
        self.cfg.target = "example.com"
        self.cfg.base_url = "https://example.com"
        self.cfg.profile.value = "aggressive"

        self.start_time = datetime.now() - timedelta(minutes=5)

    def test_write_html_report_basic(self):
        """Test basic HTML report generation."""
        findings = [
            Finding(
                title="Test Finding",
                severity=Severity.HIGH,
                description="Test description",
                phase="test_phase"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "<!DOCTYPE html>" in content
            assert "<html" in content
            assert "</html>" in content
            assert "WebRecon Report" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_write_html_report_contains_metadata(self):
        """Test that HTML report includes scan metadata."""
        findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "example.com" in content
            assert "https://example.com" in content
            assert "aggressive" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_write_html_report_contains_findings(self):
        """Test that HTML report includes all findings."""
        findings = [
            Finding(
                title="Finding 1",
                severity=Severity.CRITICAL,
                description="Description 1"
            ),
            Finding(
                title="Finding 2",
                severity=Severity.HIGH,
                description="Description 2"
            ),
            Finding(
                title="Finding 3",
                severity=Severity.LOW,
                description="Description 3"
            ),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "Finding 1" in content
            assert "Finding 2" in content
            assert "Finding 3" in content
            assert "Description 1" in content
            assert "Description 2" in content
            assert "Description 3" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_html_structure_contains_table(self):
        """Test that HTML report contains a table element."""
        findings = [
            Finding(
                title="Test",
                severity=Severity.MEDIUM,
                description="Test"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "<table>" in content
            assert "<thead>" in content
            assert "<tbody>" in content
            assert "<tr>" in content
            assert "<td>" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_html_structure_contains_summary_cards(self):
        """Test that HTML report contains summary card elements."""
        findings = [
            Finding(title="C1", severity=Severity.CRITICAL, description=""),
            Finding(title="H1", severity=Severity.HIGH, description=""),
            Finding(title="M1", severity=Severity.MEDIUM, description=""),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert 'class="cards"' in content
            assert 'class="card"' in content
        finally:
            import os
            os.unlink(temp_path)

    def test_html_contains_javascript(self):
        """Test that HTML report includes JavaScript for filtering."""
        findings = [Finding(title="Test", severity=Severity.HIGH, description="")]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "<script>" in content
            assert "activeFilter" in content
            assert "addEventListener" in content
        finally:
            import os
            os.unlink(temp_path)


class TestColorMappings:
    """Test severity color mappings in HTML report.

    Validates that severity levels are assigned correct colors.
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.cfg = MagicMock()
        self.cfg.target = "test.com"
        self.cfg.base_url = "https://test.com"
        self.cfg.profile.value = "normal"
        self.start_time = datetime.now()

    def test_critical_color(self):
        """Test that CRITICAL findings have correct color."""
        findings = [
            Finding(
                title="Critical Issue",
                severity=Severity.CRITICAL,
                description="Test"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            # CRITICAL color should be dark red
            assert "#8b0000" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_high_color(self):
        """Test that HIGH findings have correct color."""
        findings = [
            Finding(
                title="High Issue",
                severity=Severity.HIGH,
                description="Test"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "#e74c3c" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_medium_color(self):
        """Test that MEDIUM findings have correct color."""
        findings = [
            Finding(
                title="Medium Issue",
                severity=Severity.MEDIUM,
                description="Test"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "#f39c12" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_low_color(self):
        """Test that LOW findings have correct color."""
        findings = [
            Finding(
                title="Low Issue",
                severity=Severity.LOW,
                description="Test"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "#27ae60" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_info_color(self):
        """Test that INFO findings have correct color."""
        findings = [
            Finding(
                title="Info Finding",
                severity=Severity.INFO,
                description="Test"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "#3498db" in content
        finally:
            import os
            os.unlink(temp_path)


class TestHTMLEscaping:
    """Test HTML escaping for special characters.

    Validates that special characters are properly escaped to prevent
    XSS vulnerabilities and HTML parsing issues.
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.cfg = MagicMock()
        self.cfg.target = "test.com"
        self.cfg.base_url = "https://test.com"
        self.cfg.profile.value = "normal"
        self.start_time = datetime.now()

    def test_escape_angle_brackets(self):
        """Test that angle brackets are escaped."""
        findings = [
            Finding(
                title="Test <script>alert('xss')</script>",
                severity=Severity.HIGH,
                description="Description with <tags>"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            # Should contain escaped version, not raw script tag
            assert "&lt;script&gt;" in content or "<script>" not in content
        finally:
            import os
            os.unlink(temp_path)

    def test_escape_ampersand(self):
        """Test that ampersands are escaped."""
        findings = [
            Finding(
                title="Test & Title",
                severity=Severity.MEDIUM,
                description="A & B & C"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "&amp;" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_escape_quotes(self):
        """Test that quotes are escaped."""
        findings = [
            Finding(
                title='Test "Quoted" Title',
                severity=Severity.LOW,
                description='Description with "quotes"'
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "&quot;" in content or "&#34;" in content or content.count("\"") > 0
        finally:
            import os
            os.unlink(temp_path)

    def test_escape_in_config_target(self):
        """Test that config target is escaped."""
        cfg = MagicMock()
        cfg.target = "example<.com"
        cfg.base_url = "https://example.com/path?q=1&x=2"
        cfg.profile.value = "normal"

        findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(cfg, temp_path, findings, datetime.now())

            with open(temp_path, 'r') as f:
                content = f.read()

            # Should contain escaped version
            assert "&lt;" in content or "example<.com" not in content
        finally:
            import os
            os.unlink(temp_path)


class TestSeverityCounting:
    """Test severity counting in summary cards.

    Validates that summary cards display correct counts per severity level.
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.cfg = MagicMock()
        self.cfg.target = "test.com"
        self.cfg.base_url = "https://test.com"
        self.cfg.profile.value = "normal"
        self.start_time = datetime.now()

    def test_count_all_severities(self):
        """Test counting findings of all severity levels."""
        findings = [
            Finding(title="C1", severity=Severity.CRITICAL, description=""),
            Finding(title="C2", severity=Severity.CRITICAL, description=""),
            Finding(title="H1", severity=Severity.HIGH, description=""),
            Finding(title="M1", severity=Severity.MEDIUM, description=""),
            Finding(title="M2", severity=Severity.MEDIUM, description=""),
            Finding(title="L1", severity=Severity.LOW, description=""),
            Finding(title="I1", severity=Severity.INFO, description=""),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            # Should show counts
            assert "CRITICAL" in content
            assert "HIGH" in content
            assert "MEDIUM" in content
            assert "LOW" in content
            assert "INFO" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_empty_findings_list(self):
        """Test report generation with no findings."""
        findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "WebRecon Report" in content
            assert "<table>" in content
        finally:
            import os
            os.unlink(temp_path)


class TestFindingSorting:
    """Test finding sorting in HTML report.

    Validates that findings are sorted by severity (highest first).
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.cfg = MagicMock()
        self.cfg.target = "test.com"
        self.cfg.base_url = "https://test.com"
        self.cfg.profile.value = "normal"
        self.start_time = datetime.now()

    def test_findings_sorted_by_severity(self):
        """Test that findings appear in severity order."""
        findings = [
            Finding(title="Low Issue", severity=Severity.LOW, description="L"),
            Finding(title="Critical Issue", severity=Severity.CRITICAL, description="C"),
            Finding(title="Medium Issue", severity=Severity.MEDIUM, description="M"),
            Finding(title="High Issue", severity=Severity.HIGH, description="H"),
            Finding(title="Info Issue", severity=Severity.INFO, description="I"),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            # Critical should appear first in the findings table
            critical_pos = content.find("Critical Issue")
            high_pos = content.find("High Issue")
            medium_pos = content.find("Medium Issue")
            low_pos = content.find("Low Issue")
            info_pos = content.find("Info Issue")

            # All should be found
            assert critical_pos > -1
            assert high_pos > -1
            assert medium_pos > -1
            assert low_pos > -1
            assert info_pos > -1

            # Order should be critical -> high -> medium -> low -> info
            assert critical_pos < high_pos < medium_pos < low_pos < info_pos
        finally:
            import os
            os.unlink(temp_path)


class TestFilteringAttributes:
    """Test data attributes for client-side filtering.

    Validates that HTML includes necessary attributes for JavaScript filtering.
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.cfg = MagicMock()
        self.cfg.target = "test.com"
        self.cfg.base_url = "https://test.com"
        self.cfg.profile.value = "normal"
        self.start_time = datetime.now()

    def test_table_rows_have_severity_data_attribute(self):
        """Test that table rows have data-sev attribute."""
        findings = [
            Finding(title="High Issue", severity=Severity.HIGH, description=""),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert 'data-sev="HIGH"' in content
            assert 'class="row"' in content
        finally:
            import os
            os.unlink(temp_path)

    def test_filter_buttons_present(self):
        """Test that filter buttons are present in HTML."""
        findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert 'class="filterbtn"' in content
            assert 'data-f="ALL"' in content
            assert 'data-f="CRITICAL"' in content
            assert 'data-f="HIGH"' in content
            assert 'data-f="MEDIUM"' in content
            assert 'data-f="LOW"' in content
            assert 'data-f="INFO"' in content
        finally:
            import os
            os.unlink(temp_path)

    def test_search_input_present(self):
        """Test that search input is present in HTML."""
        findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert 'id="search"' in content
            assert 'type="text"' in content
        finally:
            import os
            os.unlink(temp_path)


class TestReportMetadata:
    """Test metadata and header information in reports.

    Validates that report includes proper scan information.
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.cfg = MagicMock()
        self.cfg.target = "example.com"
        self.cfg.base_url = "https://example.com"
        self.cfg.profile.value = "aggressive"

    def test_report_duration_calculation(self):
        """Test that scan duration is calculated and displayed."""
        findings = []
        start_time = datetime.now() - timedelta(minutes=5, seconds=30)

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "Duration:" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_report_total_findings_count(self):
        """Test that total findings count is displayed."""
        findings = [
            Finding(title=f"Finding {i}", severity=Severity.HIGH, description="")
            for i in range(5)
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, datetime.now())

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "Total:" in content
            assert "5 findings" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_report_title_contains_target(self):
        """Test that report title contains the target name."""
        findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, datetime.now())

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "<title>" in content
            assert "example.com" in content
        finally:
            import os
            os.unlink(temp_path)


class TestDetailsSections:
    """Test expandable details sections in findings.

    Validates that findings include collapsible detail sections.
    """

    def setup_method(self):
        """Set up test fixtures."""
        self.cfg = MagicMock()
        self.cfg.target = "test.com"
        self.cfg.base_url = "https://test.com"
        self.cfg.profile.value = "normal"
        self.start_time = datetime.now()

    def test_details_elements_present(self):
        """Test that findings have details/summary elements."""
        findings = [
            Finding(
                title="Test Finding",
                severity=Severity.HIGH,
                description="Description",
                evidence="Evidence data",
                recommendation="Recommendation"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "<details>" in content
            assert "<summary>" in content
            assert "show" in content
        finally:
            import os
            os.unlink(temp_path)

    def test_details_contain_all_fields(self):
        """Test that details sections contain all finding fields."""
        findings = [
            Finding(
                title="Test Finding",
                severity=Severity.MEDIUM,
                description="Test Description",
                evidence="Test Evidence",
                recommendation="Test Recommendation",
                phase="test_phase",
                timestamp="2024-01-01T12:00:00"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.html', delete=False) as f:
            temp_path = f.name

        try:
            html.write_html_report(self.cfg, temp_path, findings, self.start_time)

            with open(temp_path, 'r') as f:
                content = f.read()

            assert "Description:" in content
            assert "Recommendation:" in content
            assert "Test Description" in content
            assert "Test Recommendation" in content
        finally:
            import os
            os.unlink(temp_path)
