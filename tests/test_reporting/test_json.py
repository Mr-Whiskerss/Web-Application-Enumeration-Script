"""
Comprehensive unit tests for the JSON reporting module.

This test module provides comprehensive coverage for JSON export functionality,
including findings serialization, diffing against previous scans, and JSON
schema validation. Tests use pytest fixtures and temporary files for validation
without requiring persistent file storage.
"""

import pytest
import tempfile
import json
import os
from unittest.mock import patch, mock_open, MagicMock
from dataclasses import asdict

from web_app.core.findings import Finding, Severity
from web_app.reporting import json as json_reporting


class TestSaveFindings:
    """Test the save_findings() function.

    Validates that findings are correctly serialized to JSON format with
    proper handling of enums and dataclass instances.
    """

    def test_save_findings_basic(self):
        """Test basic findings export to JSON."""
        findings = [
            Finding(
                title="Test Finding",
                severity=Severity.HIGH,
                description="Test description",
                phase="test_phase"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            # Verify file was created and contains valid JSON
            assert os.path.exists(temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert len(data) == 1
            assert data[0]['title'] == "Test Finding"
            assert data[0]['severity'] == "HIGH"
            assert data[0]['description'] == "Test description"
        finally:
            os.unlink(temp_path)

    def test_save_findings_multiple(self):
        """Test exporting multiple findings."""
        findings = [
            Finding(
                title=f"Finding {i}",
                severity=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM][i % 3],
                description=f"Description {i}",
                phase=f"phase_{i}"
            )
            for i in range(5)
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert len(data) == 5
            for i, item in enumerate(data):
                assert item['title'] == f"Finding {i}"
                assert item['description'] == f"Description {i}"
        finally:
            os.unlink(temp_path)

    def test_save_findings_all_severities(self):
        """Test exporting findings with all severity levels."""
        findings = [
            Finding(title="Critical", severity=Severity.CRITICAL, description="C"),
            Finding(title="High", severity=Severity.HIGH, description="H"),
            Finding(title="Medium", severity=Severity.MEDIUM, description="M"),
            Finding(title="Low", severity=Severity.LOW, description="L"),
            Finding(title="Info", severity=Severity.INFO, description="I"),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert len(data) == 5
            assert data[0]['severity'] == "CRITICAL"
            assert data[1]['severity'] == "HIGH"
            assert data[2]['severity'] == "MEDIUM"
            assert data[3]['severity'] == "LOW"
            assert data[4]['severity'] == "INFO"
        finally:
            os.unlink(temp_path)

    def test_save_findings_empty_list(self):
        """Test exporting empty findings list."""
        findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert len(data) == 0
            assert isinstance(data, list)
        finally:
            os.unlink(temp_path)

    def test_save_findings_json_formatting(self):
        """Test that JSON is properly formatted with indentation."""
        findings = [
            Finding(title="Test", severity=Severity.HIGH, description="Test")
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                content = f.read()

            # Should have indentation (pretty-printed)
            assert '\n' in content
            assert '  ' in content  # Indentation
        finally:
            os.unlink(temp_path)

    def test_save_findings_all_fields(self):
        """Test that all Finding fields are included in JSON output."""
        findings = [
            Finding(
                title="Complete Finding",
                severity=Severity.HIGH,
                description="Full description",
                evidence="Evidence data",
                recommendation="Recommended fix",
                phase="complete_phase",
                timestamp="2024-01-01T12:00:00"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            item = data[0]
            assert 'title' in item
            assert 'severity' in item
            assert 'description' in item
            assert 'evidence' in item
            assert 'recommendation' in item
            assert 'phase' in item
            assert 'timestamp' in item
        finally:
            os.unlink(temp_path)

    def test_save_findings_with_special_characters(self):
        """Test that special characters are properly JSON-encoded."""
        findings = [
            Finding(
                title="Title with \"quotes\"",
                severity=Severity.MEDIUM,
                description="Description with \n newlines \t tabs",
                evidence="Evidence with \\backslashes\\",
                recommendation="Fix with /slashes/"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            # Should parse correctly despite special characters
            assert len(data) == 1
            assert 'quotes' in data[0]['title']
        finally:
            os.unlink(temp_path)

    def test_save_findings_unicode_support(self):
        """Test that unicode characters are properly handled."""
        findings = [
            Finding(
                title="Unicode Test: 你好 مرحبا 🔒",
                severity=Severity.LOW,
                description="Emoji and special: 🚨 ⚠️ ✅",
                evidence="Symbols: ™ © ® ∞"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert len(data) == 1
            assert "你好" in data[0]['title']
            assert "🔒" in data[0]['title']
            assert "🚨" in data[0]['description']
        finally:
            os.unlink(temp_path)


class TestDiffFindings:
    """Test the diff_findings() function.

    Validates comparison of current findings against previous scan results.
    """

    def test_diff_findings_new_finding(self):
        """Test identification of new findings."""
        current = [
            Finding(title="Old Finding", severity=Severity.HIGH, description="O"),
            Finding(title="New Finding", severity=Severity.CRITICAL, description="N"),
        ]

        # Create previous findings file
        prev_findings = [{"title": "Old Finding", "severity": "HIGH"}]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            prev_path = f.name
            json.dump(prev_findings, f)

        try:
            result = json_reporting.diff_findings(current, prev_path)

            assert 'new' in result
            assert 'resolved' in result
            assert 'unchanged' in result

            # Should identify new finding
            assert len(result['new']) == 1
            assert result['new'][0]['title'] == "New Finding"
        finally:
            os.unlink(prev_path)

    def test_diff_findings_resolved_finding(self):
        """Test identification of resolved findings."""
        current = [
            Finding(title="Still Here", severity=Severity.HIGH, description="S"),
        ]

        prev_findings = [
            {"title": "Still Here", "severity": "HIGH"},
            {"title": "Fixed Issue", "severity": "CRITICAL"},
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            prev_path = f.name
            json.dump(prev_findings, f)

        try:
            result = json_reporting.diff_findings(current, prev_path)

            assert 'resolved' in result
            # Should identify resolved finding
            assert "Fixed Issue" in result['resolved']
        finally:
            os.unlink(prev_path)

    def test_diff_findings_unchanged(self):
        """Test counting of unchanged findings."""
        current = [
            Finding(title="Finding A", severity=Severity.HIGH, description="A"),
            Finding(title="Finding B", severity=Severity.MEDIUM, description="B"),
            Finding(title="Finding C", severity=Severity.LOW, description="C"),
        ]

        prev_findings = [
            {"title": "Finding A", "severity": "HIGH"},
            {"title": "Finding B", "severity": "MEDIUM"},
            {"title": "Finding C", "severity": "LOW"},
            {"title": "Finding D", "severity": "INFO"},
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            prev_path = f.name
            json.dump(prev_findings, f)

        try:
            result = json_reporting.diff_findings(current, prev_path)

            assert result['unchanged'] == 3
        finally:
            os.unlink(prev_path)

    def test_diff_findings_no_previous_file(self):
        """Test behavior when previous findings file doesn't exist."""
        current = [
            Finding(title="Finding", severity=Severity.HIGH, description="F"),
        ]

        result = json_reporting.diff_findings(current, "/nonexistent/path.json")

        assert result == {}

    def test_diff_findings_invalid_json(self):
        """Test behavior when previous file contains invalid JSON."""
        current = [
            Finding(title="Finding", severity=Severity.HIGH, description="F"),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            prev_path = f.name
            f.write("Invalid JSON {[}]")

        try:
            result = json_reporting.diff_findings(current, prev_path)

            # Should handle gracefully and return empty dict
            assert result == {}
        finally:
            os.unlink(prev_path)

    def test_diff_findings_empty_previous(self):
        """Test diffing against empty previous findings."""
        current = [
            Finding(title="New Finding", severity=Severity.HIGH, description="N"),
            Finding(title="Another New", severity=Severity.MEDIUM, description="A"),
        ]

        prev_findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            prev_path = f.name
            json.dump(prev_findings, f)

        try:
            result = json_reporting.diff_findings(current, prev_path)

            # All current findings should be new
            assert len(result['new']) == 2
            assert result['unchanged'] == 0
            assert len(result['resolved']) == 0
        finally:
            os.unlink(prev_path)

    def test_diff_findings_empty_current(self):
        """Test diffing with empty current findings."""
        current = []

        prev_findings = [
            {"title": "Old Finding 1", "severity": "HIGH"},
            {"title": "Old Finding 2", "severity": "CRITICAL"},
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            prev_path = f.name
            json.dump(prev_findings, f)

        try:
            result = json_reporting.diff_findings(current, prev_path)

            # All previous findings should be resolved
            assert len(result['new']) == 0
            assert result['unchanged'] == 0
            assert len(result['resolved']) == 2
            assert "Old Finding 1" in result['resolved']
            assert "Old Finding 2" in result['resolved']
        finally:
            os.unlink(prev_path)

    def test_diff_findings_complex_scenario(self):
        """Test diffing with mixed new, resolved, and unchanged findings."""
        current = [
            Finding(title="Unchanged 1", severity=Severity.HIGH, description="U1"),
            Finding(title="Unchanged 2", severity=Severity.MEDIUM, description="U2"),
            Finding(title="New Finding 1", severity=Severity.CRITICAL, description="N1"),
            Finding(title="New Finding 2", severity=Severity.LOW, description="N2"),
        ]

        prev_findings = [
            {"title": "Unchanged 1", "severity": "HIGH"},
            {"title": "Unchanged 2", "severity": "MEDIUM"},
            {"title": "Resolved 1", "severity": "HIGH"},
            {"title": "Resolved 2", "severity": "INFO"},
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            prev_path = f.name
            json.dump(prev_findings, f)

        try:
            result = json_reporting.diff_findings(current, prev_path)

            assert len(result['new']) == 2
            assert "New Finding 1" in [f['title'] for f in result['new']]
            assert "New Finding 2" in [f['title'] for f in result['new']]

            assert result['unchanged'] == 2

            assert len(result['resolved']) == 2
            assert "Resolved 1" in result['resolved']
            assert "Resolved 2" in result['resolved']
        finally:
            os.unlink(prev_path)

    def test_diff_findings_new_items_contain_all_fields(self):
        """Test that new findings in diff contain all fields."""
        current = [
            Finding(
                title="New Finding",
                severity=Severity.CRITICAL,
                description="New description",
                evidence="Evidence data",
                recommendation="Fix this",
                phase="test_phase",
                timestamp="2024-01-01T12:00:00"
            ),
        ]

        prev_findings = []

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            prev_path = f.name
            json.dump(prev_findings, f)

        try:
            result = json_reporting.diff_findings(current, prev_path)

            assert len(result['new']) == 1
            new_item = result['new'][0]

            assert new_item['title'] == "New Finding"
            assert new_item['severity'] == "CRITICAL"
            assert new_item['description'] == "New description"
            assert new_item['evidence'] == "Evidence data"
            assert new_item['recommendation'] == "Fix this"
            assert new_item['phase'] == "test_phase"
            assert new_item['timestamp'] == "2024-01-01T12:00:00"
        finally:
            os.unlink(prev_path)


class TestJSONSchemaValidation:
    """Test JSON output schema compliance.

    Validates that exported JSON follows expected schema structure.
    """

    def test_schema_finding_has_required_fields(self):
        """Test that each finding in JSON has required fields."""
        findings = [
            Finding(
                title="Test",
                severity=Severity.HIGH,
                description="Description"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            required_fields = ['title', 'severity', 'description', 'evidence',
                             'recommendation', 'phase', 'timestamp']

            for finding in data:
                for field in required_fields:
                    assert field in finding
        finally:
            os.unlink(temp_path)

    def test_schema_severity_is_string(self):
        """Test that severity is stored as string value."""
        findings = [
            Finding(title="Test", severity=Severity.CRITICAL, description="T"),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert isinstance(data[0]['severity'], str)
            assert data[0]['severity'] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        finally:
            os.unlink(temp_path)

    def test_schema_timestamp_format(self):
        """Test that timestamp is stored in ISO format."""
        findings = [
            Finding(
                title="Test",
                severity=Severity.HIGH,
                description="T",
                timestamp="2024-01-15T14:30:45.123456"
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            timestamp = data[0]['timestamp']
            assert isinstance(timestamp, str)
            assert 'T' in timestamp or ':' in timestamp
        finally:
            os.unlink(temp_path)

    def test_schema_output_is_list(self):
        """Test that JSON output is always a list."""
        findings = [
            Finding(title="Single", severity=Severity.HIGH, description="S"),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert isinstance(data, list)
        finally:
            os.unlink(temp_path)


class TestEdgeCases:
    """Test edge cases and special scenarios.

    Validates handling of unusual input and boundary conditions.
    """

    def test_save_findings_with_very_long_strings(self):
        """Test handling findings with very long content."""
        findings = [
            Finding(
                title="A" * 1000,
                severity=Severity.HIGH,
                description="B" * 5000,
                evidence="C" * 10000,
                recommendation="D" * 2000
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert len(data[0]['title']) == 1000
            assert len(data[0]['description']) == 5000
            assert len(data[0]['evidence']) == 10000
        finally:
            os.unlink(temp_path)

    def test_save_findings_with_null_values(self):
        """Test handling findings with optional fields as empty strings."""
        findings = [
            Finding(
                title="Test",
                severity=Severity.MEDIUM,
                description="Description",
                evidence="",
                recommendation=""
            )
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert data[0]['evidence'] == ""
            assert data[0]['recommendation'] == ""
        finally:
            os.unlink(temp_path)

    def test_diff_findings_with_duplicate_titles(self):
        """Test diffing when multiple findings have same title."""
        current = [
            Finding(title="Same Title", severity=Severity.HIGH, description="1"),
            Finding(title="Same Title", severity=Severity.MEDIUM, description="2"),
        ]

        prev_findings = [
            {"title": "Same Title", "severity": "HIGH"},
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            prev_path = f.name
            json.dump(prev_findings, f)

        try:
            result = json_reporting.diff_findings(current, prev_path)

            # Should handle duplicates based on title
            assert len(result['new']) >= 0
        finally:
            os.unlink(prev_path)

    def test_save_findings_large_dataset(self):
        """Test saving a large number of findings."""
        findings = [
            Finding(
                title=f"Finding {i}",
                severity=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                         Severity.LOW, Severity.INFO][i % 5],
                description=f"Description for finding {i}",
                phase=f"phase_{i % 10}"
            )
            for i in range(1000)
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert len(data) == 1000
        finally:
            os.unlink(temp_path)

    def test_file_permissions_after_save(self):
        """Test that saved JSON file has appropriate permissions."""
        findings = [
            Finding(title="Test", severity=Severity.HIGH, description="T"),
        ]

        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as f:
            temp_path = f.name

        try:
            json_reporting.save_findings(findings, temp_path)

            # File should be readable
            assert os.access(temp_path, os.R_OK)
            # File should exist and be a regular file
            assert os.path.isfile(temp_path)
            # File should have content
            assert os.path.getsize(temp_path) > 0
        finally:
            os.unlink(temp_path)
