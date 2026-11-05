"""JSON report generation for WebRecon scan findings.

This module provides functions for exporting scan findings to JSON format,
including findings serialization and diffing against previous scan results.
Exported JSON follows a standard schema with title, severity, description,
evidence, recommendation, phase, and timestamp fields per finding.
"""

import os
import json
from dataclasses import asdict
from typing import List, Dict

# Import data structures from core module
from web_app.core.findings import Finding


def save_findings(findings: List[Finding], path: str):
    """Export findings as a JSON file.

    Serializes a list of Finding dataclass instances to JSON format with
    automatic handling of non-standard types (e.g., Enums, timestamps).

    Args:
        findings: List of Finding objects to export
        path: Destination file path for JSON output

    Returns:
        None - writes directly to file
    """
    with open(path, 'w') as fh:
        json.dump([asdict(f) for f in findings], fh, indent=2, default=str)


def diff_findings(current: List[Finding], prev_file: str) -> Dict:
    """Compare current findings against a previous scan's JSON export.

    Loads a previous findings JSON file and compares it against the current
    findings list, identifying new issues, resolved issues, and unchanged findings.

    Args:
        current: List of Finding objects from current scan
        prev_file: Path to previous scan's findings JSON file

    Returns:
        Dict with keys:
            - new: List of new finding dicts (not in previous scan)
            - resolved: List of finding titles resolved since previous scan
            - unchanged: Count of findings that appear in both scans
        Returns empty dict if previous file doesn't exist or parsing fails
    """
    if not os.path.exists(prev_file):
        return {}
    try:
        prev = {f['title'] for f in json.load(open(prev_file))}
        curr = {f.title for f in current}
        return {
            "new":       [asdict(f) for f in current if f.title not in prev],
            "resolved":  list(prev - curr),
            "unchanged": len(curr & prev),
        }
    except Exception:
        return {}
