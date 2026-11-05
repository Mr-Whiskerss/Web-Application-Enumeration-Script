"""
WebRecon - Comprehensive Web Application Reconnaissance & Enumeration

A single-tool framework that orchestrates passive OSINT, active reconnaissance,
content discovery, vulnerability probing, and reporting for web-application
penetration testing.

Modules:
- core: Core functionality (session, state, findings)
- phases: Scanning phases (passive, active, discovery, vulns, etc.)
- integrations: External integrations (webhooks, pentestdb)
- reporting: Report generation (markdown, html, json)
- utils: Utility helpers
"""

__version__ = "3.3.0"
__author__ = "MrWhiskers"
__license__ = "GPL-3.0"

from .core import (
    RateLimitedSession,
    make_session,
    detect_scheme,
    revalidate_session,
    ScanState,
    ScopeChecker,
    DiscoveredState,
    Finding,
    Severity,
    add_finding,
    webhook_notify,
    pentestdb_push,
    save_findings,
)

__all__ = [
    "__version__",
    "RateLimitedSession",
    "make_session",
    "detect_scheme",
    "revalidate_session",
    "ScanState",
    "ScopeChecker",
    "DiscoveredState",
    "Finding",
    "Severity",
    "add_finding",
    "webhook_notify",
    "pentestdb_push",
    "save_findings",
]
