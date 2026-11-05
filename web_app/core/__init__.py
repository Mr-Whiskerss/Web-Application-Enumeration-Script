"""
WebRecon Core Module

Core functionality for scanning:
- Session management (HTTP requests with rate limiting)
- Scan state (resumability, phase tracking)
- Finding management (collection, deduplication, reporting)
- Scope checking (CIDR/domain validation)
- Discovered state (shared state across phases)
"""

from .session import RateLimitedSession, make_session, detect_scheme, revalidate_session
from .state import ScanState, ScopeChecker, DiscoveredState
from .findings import Finding, add_finding, webhook_notify, pentestdb_push, save_findings

__all__ = [
    "RateLimitedSession",
    "make_session",
    "detect_scheme",
    "revalidate_session",
    "ScanState",
    "ScopeChecker",
    "DiscoveredState",
    "Finding",
    "add_finding",
    "webhook_notify",
    "pentestdb_push",
    "save_findings",
]
