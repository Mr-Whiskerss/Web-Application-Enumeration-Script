"""
Unit tests for discovery module.

Tests DiscoveredState singleton instance and its usage across the application.
"""

import pytest
from pathlib import Path
from unittest.mock import patch
import threading

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from web_app.core.discovery import DISCOVERED, DiscoveredState


class TestDiscoveredSingleton:
    """Test the DISCOVERED singleton instance."""

    def setup_method(self):
        """Reset DISCOVERED state before each test."""
        DISCOVERED.urls.clear()
        DISCOVERED.params.clear()
        DISCOVERED.endpoints.clear()

    def test_discovered_is_singleton(self):
        """Test that DISCOVERED is a DiscoveredState instance."""
        assert isinstance(DISCOVERED, DiscoveredState)

    def test_discovered_persists_across_imports(self):
        """Test that DISCOVERED state persists across module reloads."""
        # Add some data
        DISCOVERED.add_urls(["http://example.com/api"])
        initial_count = len(DISCOVERED.urls)

        # Import again
        from web_app.core.discovery import DISCOVERED as discovered2

        # Should have same data
        assert len(discovered2.urls) == initial_count

    def test_discovered_accumulates_data(self):
        """Test that DISCOVERED accumulates data from multiple calls."""
        DISCOVERED.add_urls(["http://example.com/api"])
        assert len(DISCOVERED.urls) == 1

        DISCOVERED.add_urls(["http://example.com/admin"])
        assert len(DISCOVERED.urls) == 2

        DISCOVERED.add_params(["id", "token"])
        assert len(DISCOVERED.params) == 2

    def test_discovered_adds_multiple_urls(self):
        """Test adding multiple URLs to singleton."""
        urls = [
            "http://example.com/api/users",
            "http://example.com/api/posts",
            "http://example.com/admin",
        ]
        DISCOVERED.add_urls(urls)
        assert len(DISCOVERED.urls) == 3

    def test_discovered_adds_multiple_params(self):
        """Test adding multiple parameters to singleton."""
        params = ["search", "filter", "sort", "page", "limit"]
        DISCOVERED.add_params(params)
        assert len(DISCOVERED.params) == 5

    def test_discovered_get_urls_with_params(self):
        """Test getting URLs with query parameters."""
        DISCOVERED.add_urls([
            "http://example.com/api?id=1&token=abc",
            "http://example.com/admin?user=test",
            "http://example.com/static/file.js",  # No query params
        ])

        result = DISCOVERED.get_urls_with_params()
        assert len(result) == 2

    def test_discovered_endpoints_extraction(self):
        """Test that endpoints are automatically extracted from URLs."""
        DISCOVERED.add_urls([
            "http://example.com/api/users?id=1",
            "http://example.com/api/posts",
            "http://example.com/admin",
        ])

        assert "/api/users" in DISCOVERED.endpoints
        assert "/api/posts" in DISCOVERED.endpoints
        assert "/admin" in DISCOVERED.endpoints

    def test_discovered_params_extraction(self):
        """Test that parameters are automatically extracted from URLs."""
        DISCOVERED.add_urls([
            "http://example.com/search?q=test&page=1",
            "http://example.com/api?token=abc",
        ])

        assert "q" in DISCOVERED.params
        assert "page" in DISCOVERED.params
        assert "token" in DISCOVERED.params

    def test_discovered_thread_safety(self):
        """Test that DISCOVERED is thread-safe."""
        errors = []

        def worker(thread_id):
            try:
                for i in range(50):
                    DISCOVERED.add_urls([f"http://example.com/url{thread_id}_{i}"])
                    DISCOVERED.add_params([f"param{thread_id}_{i}"])
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(DISCOVERED.urls) > 0
        assert len(DISCOVERED.params) > 0

    def test_discovered_mixed_operations(self):
        """Test mixed operations on DISCOVERED."""
        # Add initial URLs
        DISCOVERED.add_urls([
            "http://example.com/api/v1/users?id=1&name=test",
            "http://example.com/api/v1/posts?post_id=5",
        ])

        # Add more parameters manually
        DISCOVERED.add_params(["search", "filter"])

        # Add more URLs
        DISCOVERED.add_urls([
            "http://example.com/api/v2/comments?id=1&sort=date",
        ])

        # Verify accumulated state
        assert len(DISCOVERED.urls) == 3
        assert "id" in DISCOVERED.params
        assert "name" in DISCOVERED.params
        assert "post_id" in DISCOVERED.params
        assert "search" in DISCOVERED.params
        assert "filter" in DISCOVERED.params
        assert "sort" in DISCOVERED.params

    def test_discovered_deduplicates_urls(self):
        """Test that DISCOVERED deduplicates URLs."""
        DISCOVERED.add_urls([
            "http://example.com/api",
            "http://example.com/api",
        ])
        assert len(DISCOVERED.urls) == 1

    def test_discovered_deduplicates_params(self):
        """Test that DISCOVERED deduplicates parameters."""
        DISCOVERED.add_params(["search", "search", "filter", "filter"])
        assert len(DISCOVERED.params) == 2

    def test_discovered_handles_malformed_urls(self):
        """Test that DISCOVERED handles malformed URLs gracefully."""
        DISCOVERED.add_urls([
            "not a url",
            "http://example.com/valid",
            "ftp://invalid.scheme",
            None,
            "",
        ])

        # Should have at least the valid URL
        assert "http://example.com/valid" in DISCOVERED.urls

    def test_discovered_complex_query_parsing(self):
        """Test complex query parameter parsing."""
        DISCOVERED.add_urls([
            "http://example.com/search?q=test&page=1&sort=date&direction=asc&limit=50",
        ])

        expected_params = {"q", "page", "sort", "direction", "limit"}
        assert expected_params.issubset(DISCOVERED.params)

    def test_discovered_get_urls_with_params_limit(self):
        """Test limit parameter in get_urls_with_params."""
        urls = [f"http://example.com/api?id={i}" for i in range(100)]
        DISCOVERED.add_urls(urls)

        result = DISCOVERED.get_urls_with_params(limit=20)
        assert len(result) <= 20

    def test_discovered_no_urls_with_params(self):
        """Test getting URLs with params when none have query strings."""
        DISCOVERED.add_urls([
            "http://example.com",
            "http://example.com/api",
            "http://example.com/admin",
        ])

        result = DISCOVERED.get_urls_with_params()
        assert result == []

    def test_discovered_real_world_scenario(self):
        """Test real-world scenario of progressive discovery."""
        # Phase 1: Initial passive reconnaissance
        DISCOVERED.add_urls([
            "http://example.com",
            "http://example.com/api",
            "http://example.com/admin",
        ])

        phase1_urls = len(DISCOVERED.urls)
        assert phase1_urls == 3

        # Phase 2: Active enumeration discovers more
        DISCOVERED.add_urls([
            "http://example.com/api/users?page=1",
            "http://example.com/api/posts?id=1&token=abc",
            "http://example.com/admin/dashboard",
        ])

        assert len(DISCOVERED.urls) >= 6

        # Phase 3: Parameter discovery
        DISCOVERED.add_params(["search", "filter", "sort"])
        assert len(DISCOVERED.params) >= 6  # From URLs + manual

        # Verify final state
        urls_with_params = DISCOVERED.get_urls_with_params()
        assert len(urls_with_params) >= 2

        endpoints = DISCOVERED.endpoints
        assert "/api" in endpoints or "/api/users" in endpoints


class TestDiscoveryIntegration:
    """Integration tests for discovery module."""

    def setup_method(self):
        """Reset state before each test."""
        DISCOVERED.urls.clear()
        DISCOVERED.params.clear()
        DISCOVERED.endpoints.clear()

    def test_discovery_workflow_sequential(self):
        """Test sequential discovery workflow."""
        # Step 1: Initial URL discovery
        initial_urls = [
            "http://example.com/",
            "http://example.com/api/",
        ]
        DISCOVERED.add_urls(initial_urls)

        # Step 2: Deep crawl discovers endpoints with params
        crawled_urls = [
            "http://example.com/api/users?id=1&role=admin",
            "http://example.com/api/posts?page=1&limit=10",
            "http://example.com/search?q=test",
        ]
        DISCOVERED.add_urls(crawled_urls)

        # Step 3: Parameter fuzzing finds more params
        discovered_params = ["token", "api_key", "timestamp"]
        DISCOVERED.add_params(discovered_params)

        # Verify comprehensive discovery
        assert len(DISCOVERED.urls) == len(initial_urls) + len(crawled_urls)
        assert len(DISCOVERED.params) >= 3 + 3  # extracted + manual

    def test_discovery_thread_safe_accumulation(self):
        """Test thread-safe accumulation of discovery data."""
        import random

        def discovery_worker(worker_id):
            for i in range(20):
                urls = [f"http://example.com/endpoint{worker_id}_{i}_{j}" for j in range(3)]
                DISCOVERED.add_urls(urls)

                params = [f"param{worker_id}_{i}_{j}" for j in range(2)]
                DISCOVERED.add_params(params)

                time.sleep(random.uniform(0.001, 0.01))

        import time
        threads = [threading.Thread(target=discovery_worker, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Verify no data loss
        assert len(DISCOVERED.urls) > 50
        assert len(DISCOVERED.params) > 40
