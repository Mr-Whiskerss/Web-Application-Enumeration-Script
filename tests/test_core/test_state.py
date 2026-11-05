"""
Unit tests for state module.

Tests ScanState (mark, done, resume), ScopeChecker (IPv4/IPv6/domain validation),
and DiscoveredState (add_urls, add_params, thread safety).
"""

import pytest
import json
import os
import threading
from pathlib import Path
from unittest.mock import patch, Mock
from urllib.parse import urlparse

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from web_app.core.state import (
    ScanState,
    ScopeChecker,
    DiscoveredState,
)


class TestScanState:
    """Test ScanState class for scan progress tracking."""

    def test_scanstate_creates_new_state(self, temp_state_file):
        """Test creating a new ScanState initializes empty."""
        state = ScanState(temp_state_file, "example.com")
        assert state._target == "example.com"
        assert state._done == []

    def test_scanstate_marks_phase_complete(self, temp_state_file):
        """Test marking a phase as complete."""
        state = ScanState(temp_state_file, "example.com")
        state.mark("passive")
        assert state.done("passive") is True

    def test_scanstate_done_returns_false_for_unfinished(self, temp_state_file):
        """Test done() returns False for incomplete phases."""
        state = ScanState(temp_state_file, "example.com")
        assert state.done("active") is False

    def test_scanstate_marks_multiple_phases(self, temp_state_file):
        """Test marking multiple phases."""
        state = ScanState(temp_state_file, "example.com")
        state.mark("passive")
        state.mark("dns_security")
        state.mark("active")

        assert state.done("passive") is True
        assert state.done("dns_security") is True
        assert state.done("active") is True

    def test_scanstate_persists_to_file(self, temp_state_file):
        """Test that marked phases are persisted to file."""
        state = ScanState(temp_state_file, "example.com")
        state.mark("passive")
        state.mark("active")

        assert os.path.exists(temp_state_file)
        with open(temp_state_file, "r") as f:
            data = json.load(f)

        assert "passive" in data["done"]
        assert "active" in data["done"]
        assert data["target"] == "example.com"

    def test_scanstate_resumes_from_file(self, sample_state_file):
        """Test resuming scan from existing state file."""
        state = ScanState(sample_state_file, "example.com")

        assert state.done("passive") is True
        assert state.done("dns_security") is True
        assert state.done("active") is False

    def test_scanstate_clears_old_target_state(self, temp_state_file, temp_dir):
        """Test that state for different target is cleared."""
        # First, create state for target1
        state1 = ScanState(temp_state_file, "target1.com")
        state1.mark("passive")

        with open(temp_state_file, "r") as f:
            data1 = json.load(f)
        assert data1["target"] == "target1.com"

        # Now create state for target2 with same file
        state2 = ScanState(temp_state_file, "target2.com")
        # File should be cleared
        assert not os.path.exists(temp_state_file) or state2._done == []

    def test_scanstate_handles_corrupted_json(self, temp_state_file):
        """Test that corrupted state file is handled gracefully."""
        with open(temp_state_file, "w") as f:
            f.write("not valid json: {[")

        state = ScanState(temp_state_file, "example.com")
        assert state._done == []

    def test_scanstate_mark_prevents_duplicates(self, temp_state_file):
        """Test that marking same phase twice doesn't create duplicates."""
        state = ScanState(temp_state_file, "example.com")
        state.mark("passive")
        state.mark("passive")

        with open(temp_state_file, "r") as f:
            data = json.load(f)
        assert data["done"].count("passive") == 1

    def test_scanstate_clear(self, temp_state_file):
        """Test clearing state file."""
        state = ScanState(temp_state_file, "example.com")
        state.mark("passive")
        assert os.path.exists(temp_state_file)

        state.clear()
        assert state._done == []

    def test_scanstate_preserves_timestamps(self, temp_state_file):
        """Test that start and update timestamps are preserved."""
        state = ScanState(temp_state_file, "example.com")
        state.mark("passive")

        with open(temp_state_file, "r") as f:
            data = json.load(f)

        assert "start" in data
        assert "updated" in data
        assert data["start"] is not None
        assert data["updated"] is not None


class TestScopeChecker:
    """Test ScopeChecker class for target validation."""

    def test_scope_checker_no_scope_file(self):
        """Test ScopeChecker with no scope file allows everything."""
        checker = ScopeChecker()
        assert checker.enabled is False
        assert checker.check("example.com") is True
        assert checker.check("192.168.1.1") is True

    def test_scope_checker_ipv4_literal(self, sample_scope_file):
        """Test IPv4 literal matching."""
        checker = ScopeChecker(sample_scope_file)
        assert checker.check("192.168.1.50") is True
        assert checker.check("192.168.2.50") is False

    def test_scope_checker_ipv4_cidr(self, sample_scope_file):
        """Test IPv4 CIDR range checking."""
        checker = ScopeChecker(sample_scope_file)
        assert checker.check("10.0.0.1") is True
        assert checker.check("10.255.255.255") is True
        assert checker.check("172.16.0.1") is False

    def test_scope_checker_ipv6_literal(self, sample_scope_file):
        """Test IPv6 literal matching."""
        checker = ScopeChecker(sample_scope_file)
        assert checker.check("2001:db8::1") is True
        assert checker.check("2001:db9::1") is False

    def test_scope_checker_domain_exact_match(self, sample_scope_file):
        """Test exact domain matching."""
        checker = ScopeChecker(sample_scope_file)
        assert checker.check("example.com") is True
        assert checker.check("test.com") is False

    def test_scope_checker_domain_subdomain(self, sample_scope_file):
        """Test subdomain matching."""
        checker = ScopeChecker(sample_scope_file)
        assert checker.check("sub.example.com") is True
        assert checker.check("deep.sub.example.com") is True
        assert checker.check("other.com") is False

    def test_scope_checker_wildcard_domain(self, sample_scope_file):
        """Test wildcard domain matching."""
        checker = ScopeChecker(sample_scope_file)
        assert checker.check("internal.local") is True
        assert checker.check("api.internal.local") is True
        assert checker.check("external.local") is False

    def test_scope_checker_case_insensitive(self, sample_scope_file):
        """Test that domain checking is case-insensitive."""
        checker = ScopeChecker(sample_scope_file)
        assert checker.check("EXAMPLE.COM") is True
        assert checker.check("Example.Com") is True
        assert checker.check("example.com") is True

    def test_scope_checker_dns_resolution(self, sample_scope_file):
        """Test DNS resolution for IP-based scope validation."""
        checker = ScopeChecker(sample_scope_file)
        # This would require mocking socket.gethostbyname
        with patch('socket.gethostbyname') as mock_gethostbyname:
            mock_gethostbyname.return_value = "192.168.1.10"
            assert checker.check("internal-host.local") is True

    def test_scope_checker_invalid_domain(self, sample_scope_file):
        """Test checking invalid domain returns False."""
        checker = ScopeChecker(sample_scope_file)
        with patch('socket.gethostbyname') as mock_gethostbyname:
            mock_gethostbyname.side_effect = OSError("DNS resolution failed")
            assert checker.check("unknown.invalid") is False

    def test_scope_checker_empty_scope_file(self, temp_dir):
        """Test empty scope file allows nothing."""
        scope_file = os.path.join(temp_dir, "empty_scope.txt")
        with open(scope_file, "w") as f:
            f.write("# Only comments\n")

        checker = ScopeChecker(scope_file)
        assert checker.check("example.com") is False

    def test_scope_checker_ignores_comments(self, temp_dir):
        """Test that comments in scope file are ignored."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        with open(scope_file, "w") as f:
            f.write("# This is a comment\n")
            f.write("example.com\n")
            f.write("# Another comment\n")
            f.write("192.168.0.0/24\n")

        checker = ScopeChecker(scope_file)
        assert checker.check("example.com") is True
        assert checker.check("192.168.0.50") is True

    def test_scope_checker_ignores_empty_lines(self, temp_dir):
        """Test that empty lines are ignored."""
        scope_file = os.path.join(temp_dir, "scope.txt")
        with open(scope_file, "w") as f:
            f.write("\n")
            f.write("example.com\n")
            f.write("\n\n")
            f.write("192.168.0.0/24\n")
            f.write("\n")

        checker = ScopeChecker(scope_file)
        assert checker.check("example.com") is True
        assert checker.check("192.168.0.1") is True


class TestDiscoveredState:
    """Test DiscoveredState for tracking discovered URLs/parameters."""

    def test_discovered_state_init(self):
        """Test DiscoveredState initialization."""
        discovered = DiscoveredState()
        assert discovered.urls == set()
        assert discovered.params == set()
        assert discovered.endpoints == set()

    def test_add_urls_single(self):
        """Test adding a single URL."""
        discovered = DiscoveredState()
        discovered.add_urls(["http://example.com/api/users"])
        assert "http://example.com/api/users" in discovered.urls

    def test_add_urls_multiple(self):
        """Test adding multiple URLs."""
        discovered = DiscoveredState()
        urls = [
            "http://example.com/api/users",
            "http://example.com/api/posts",
            "http://example.com/admin",
        ]
        discovered.add_urls(urls)
        assert len(discovered.urls) == 3
        for url in urls:
            assert url in discovered.urls

    def test_add_urls_extracts_endpoints(self):
        """Test that adding URLs extracts endpoints."""
        discovered = DiscoveredState()
        discovered.add_urls(["http://example.com/api/users?id=1", "http://example.com/admin"])
        assert "/api/users" in discovered.endpoints
        assert "/admin" in discovered.endpoints

    def test_add_urls_extracts_parameters(self):
        """Test that adding URLs extracts query parameters."""
        discovered = DiscoveredState()
        discovered.add_urls([
            "http://example.com/search?q=test&page=1",
            "http://example.com/api?token=abc&user=test",
        ])
        assert "q" in discovered.params
        assert "page" in discovered.params
        assert "token" in discovered.params
        assert "user" in discovered.params

    def test_add_urls_deduplicates(self):
        """Test that duplicate URLs are deduplicated."""
        discovered = DiscoveredState()
        discovered.add_urls([
            "http://example.com/api",
            "http://example.com/api",
            "http://example.com/api",
        ])
        assert len(discovered.urls) == 1

    def test_add_urls_ignores_empty(self):
        """Test that empty URLs are ignored."""
        discovered = DiscoveredState()
        discovered.add_urls(["http://example.com", "", "http://example.com/api", None])
        assert len(discovered.urls) == 2

    def test_add_urls_handles_malformed(self):
        """Test that malformed URLs are handled gracefully."""
        discovered = DiscoveredState()
        discovered.add_urls(["not a valid url", "http://example.com/valid"])
        assert "http://example.com/valid" in discovered.urls

    def test_add_params_single(self):
        """Test adding a single parameter."""
        discovered = DiscoveredState()
        discovered.add_params(["search"])
        assert "search" in discovered.params

    def test_add_params_multiple(self):
        """Test adding multiple parameters."""
        discovered = DiscoveredState()
        discovered.add_params(["search", "filter", "sort", "page"])
        assert len(discovered.params) == 4
        assert "search" in discovered.params

    def test_add_params_deduplicates(self):
        """Test that duplicate parameters are deduplicated."""
        discovered = DiscoveredState()
        discovered.add_params(["search", "search", "filter", "filter"])
        assert len(discovered.params) == 2

    def test_add_params_ignores_empty(self):
        """Test that empty parameters are ignored."""
        discovered = DiscoveredState()
        discovered.add_params(["search", "", None, "filter"])
        assert len(discovered.params) == 2

    def test_get_urls_with_params_limit(self):
        """Test getting URLs with parameters respects limit."""
        discovered = DiscoveredState()
        urls = [f"http://example.com/api?id={i}" for i in range(100)]
        discovered.add_urls(urls)

        result = discovered.get_urls_with_params(limit=50)
        assert len(result) == 50

    def test_get_urls_with_params_empty(self):
        """Test getting URLs with parameters when none exist."""
        discovered = DiscoveredState()
        discovered.add_urls(["http://example.com", "http://example.com/api"])
        result = discovered.get_urls_with_params()
        assert result == []

    def test_discovered_state_thread_safety(self):
        """Test that DiscoveredState is thread-safe."""
        discovered = DiscoveredState()
        results = []

        def add_urls():
            for i in range(100):
                discovered.add_urls([f"http://example.com/url{i}"])

        threads = [threading.Thread(target=add_urls) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Should have 500 URLs without duplication issues
        assert len(discovered.urls) >= 100

    def test_discovered_state_mixed_operations_thread_safety(self):
        """Test thread safety with mixed add_urls and add_params."""
        discovered = DiscoveredState()
        urls = [f"http://example.com/api?param{i}=value{i}" for i in range(100)]

        def add_urls_thread():
            discovered.add_urls(urls)

        def add_params_thread():
            for i in range(100):
                discovered.add_params([f"param{i}"])

        def get_state_thread():
            for _ in range(50):
                _ = discovered.get_urls_with_params()

        threads = [
            threading.Thread(target=add_urls_thread),
            threading.Thread(target=add_params_thread),
            threading.Thread(target=get_state_thread),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify no crashes and data is consistent
        assert len(discovered.urls) > 0


class TestDiscoveredStateIntegration:
    """Integration tests for DiscoveredState."""

    def test_discovered_state_workflow(self):
        """Test typical workflow of discovering state."""
        discovered = DiscoveredState()

        # Initial discovery
        discovered.add_urls([
            "http://example.com/api/v1/users?id=1&token=abc",
            "http://example.com/api/v1/posts?page=1&limit=10",
            "http://example.com/admin",
        ])

        # Query discovered state
        params_with_query = discovered.get_urls_with_params()
        assert len(params_with_query) == 2
        assert "id" in discovered.params
        assert "token" in discovered.params
        assert "page" in discovered.params

        # Further discovery
        discovered.add_urls([
            "http://example.com/api/v1/comments?post_id=5&sort=date",
        ])
        discovered.add_params(["filter", "search"])

        # Verify accumulated state
        assert len(discovered.urls) == 4
        assert len(discovered.params) >= 6
        assert "/api/v1/users" in discovered.endpoints
        assert "/api/v1/posts" in discovered.endpoints
        assert "/api/v1/comments" in discovered.endpoints
