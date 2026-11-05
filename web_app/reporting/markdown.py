"""
Markdown reporting module for WebRecon scan findings.

This module provides utilities for generating markdown-formatted reports from
scan findings, including functions for formatting individual findings,
creating markdown sections, and managing output files.
"""

import threading
from typing import List
from datetime import datetime
from dataclasses import asdict

# Import severity and Finding types from core
from web_app.core.findings import Finding, Severity


# ═════════════════════════════════════════════════════════════════════════════
# MARKDOWN OUTPUT HELPERS
# ═════════════════════════════════════════════════════════════════════════════

_log_lock = threading.Lock()


def _log(output_file: str, msg: str):
    """Write message to output markdown file in thread-safe manner.

    Args:
        output_file: Path to the output markdown file.
        msg: Message to append to the file.
    """
    with _log_lock:
        with open(output_file, 'a') as fh:
            fh.write(msg + '\n')


def section(title: str, output_file: str):
    """Create a new markdown section with decorative separator.

    Args:
        title: Section title to display.
        output_file: Path to the output markdown file.
    """
    _log(output_file, f"\n\n---\n# {title}\n")


def format_finding_markdown(f: Finding) -> str:
    """Format a single finding as markdown text.

    Generates a markdown-formatted finding with severity icon, title,
    phase, timestamp, description, evidence, and recommendation.

    Args:
        f: Finding object to format.

    Returns:
        Formatted markdown string for the finding.
    """
    icons = {
        Severity.INFO: "ℹ️",
        Severity.LOW: "🟢",
        Severity.MEDIUM: "🟡",
        Severity.HIGH: "🔴",
        Severity.CRITICAL: "🚨"
    }
    icon = icons.get(f.severity, "")
    lines = [
        f"\n### {icon} [{f.severity.value}] {f.title}",
        f"**Phase:** {f.phase}  |  **Time:** {f.timestamp}\n",
        f"**Description:** {f.description}\n",
    ]
    if f.evidence:
        lines.append(f"**Evidence:**\n```\n{f.evidence[:1500]}\n```\n")
    if f.recommendation:
        lines.append(f"**Recommendation:** {f.recommendation}\n")
    lines.append("---")
    return '\n'.join(lines)


def save_findings_markdown(findings: List[Finding], path: str, cfg=None):
    """Export findings as a markdown report file.

    Generates a comprehensive markdown report with all findings sorted by
    severity, including metadata and findings formatted with all details.

    Args:
        findings: List of Finding objects to export.
        path: Output path for the markdown report.
        cfg: Optional ScanConfig object for metadata (target, profile, etc.).
    """
    with open(path, 'w') as fh:
        # Write header
        fh.write("# WebRecon Scan Report\n\n")

        if cfg:
            fh.write("## Scan Metadata\n\n")
            fh.write(f"- **Target:** {cfg.target}\n")
            fh.write(f"- **Base URL:** {cfg.base_url}\n")
            fh.write(f"- **Profile:** {cfg.profile.value}\n")
            fh.write(f"- **Scan Timestamp:** {datetime.now().isoformat()}\n\n")

        # Summary by severity
        severity_counts = {}
        for f in findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        if severity_counts:
            fh.write("## Finding Summary\n\n")
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                count = severity_counts.get(sev, 0)
                if count > 0:
                    fh.write(f"- **{sev}:** {count}\n")
            fh.write(f"\n**Total:** {len(findings)} findings\n\n")

        # Write findings sorted by severity
        fh.write("## Findings\n\n")
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.severity, 5))

        for f in sorted_findings:
            fh.write(format_finding_markdown(f))
            fh.write("\n")


def log_finding_to_report(f: Finding, output_file: str):
    """Log a finding to the markdown report file.

    Appends a formatted finding to an existing markdown report file.
    Typically called as findings are discovered during scanning.

    Args:
        f: Finding object to append to report.
        output_file: Path to the output markdown file.
    """
    fh_content = format_finding_markdown(f)
    _log(output_file, fh_content)
