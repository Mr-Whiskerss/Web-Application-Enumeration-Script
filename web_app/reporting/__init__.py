"""
WebRecon Reporting

Report generation in multiple formats:
- markdown: Markdown reports
- html: Interactive HTML reports
- json: JSON findings export
"""

from .html import write_html_report
from .json import save_findings, diff_findings

__all__ = ["write_html_report", "save_findings", "diff_findings"]
