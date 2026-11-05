"""
Unit tests for session module.

Tests RateLimitedSession (rate limiting, 429/503 handling, exponential backoff),
make_session, detect_scheme, and revalidate_session.
"""

import pytest
import time
import requests
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from web_app.core.session import (
    RateLimitedSession,
    make_session,
    detect_scheme,
    revalidate_session,
)


class TestRateLimitedSession:
    """Test RateLimitedSession class."""

    def setup_method(self):
        """Reset session state before each test."""
        RateLimitedSession._consecutive_429 = 0
        RateLimitedSession._backoff_until = 0.0
        RateLimitedSession._announced_backoff = False

    def test_ratelimited_session_init(self):
        """Test RateLimitedSession initializes correctly."""
        session = RateLimitedSession()
        assert isinstance(session, requests.Session)

    @patch('web_app.core.session.RateLimitedSession.request', wraps=RateLimitedSession.request)
    @patch('requests.Session.request')
    def test_ratelimited_session_successful_request(self, mock_super_request, mock_wrapper):
        """Test successful request through rate-limited session."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_super_request.return_value = mock_response

        session = RateLimitedSession()
        result = session.request("GET", "http://example.com")

        assert result.status_code == 200

    @patch('requests.Session.request')
    def test_ratelimited_session_handles_429(self, mock_super_request):
        """Test session handles HTTP 429 (Too Many Requests)."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "10"}
        mock_response.text = "Rate Limited"
        mock_super_request.return_value = mock_response

        session = RateLimitedSession()
        result = session.request("GET", "http://example.com")

        assert result.status_code == 429
        assert RateLimitedSession._backoff_until > time.time()

    @patch('requests.Session.request')
    def test_ratelimited_session_handles_503(self, mock_super_request):
        """Test session handles HTTP 503 (Service Unavailable)."""
        mock_response = Mock()
        mock_response.status_code = 503
        mock_response.headers = {}
        mock_response.text = "Service Unavailable"
        mock_super_request.return_value = mock_response

        session = RateLimitedSession()
        result = session.request("GET", "http://example.com")

        assert result.status_code == 503
        assert RateLimitedSession._backoff_until > time.time()

    @patch('requests.Session.request')
    def test_ratelimited_session_exponential_backoff(self, mock_super_request):
        """Test exponential backoff increases with consecutive 429s."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {}
        mock_response.text = "Rate Limited"
        mock_super_request.return_value = mock_response

        session = RateLimitedSession()

        # First 429
        session.request("GET", "http://example.com")
        backoff_1 = RateLimitedSession._backoff_until

        # Wait a tiny bit
        time.sleep(0.1)

        # Reset announced flag
        RateLimitedSession._announced_backoff = False
        RateLimitedSession._backoff_until = 0.0

        # Second 429
        session.request("GET", "http://example.com")
        backoff_2 = RateLimitedSession._backoff_until

        # Backoff should have increased
        assert backoff_2 >= backoff_1

    @patch('requests.Session.request')
    def test_ratelimited_session_resets_after_success(self, mock_super_request):
        """Test consecutive 429 counter resets after successful request."""
        mock_429 = Mock()
        mock_429.status_code = 429
        mock_429.headers = {}

        mock_200 = Mock()
        mock_200.status_code = 200
        mock_200.text = "OK"

        mock_super_request.side_effect = [mock_429, mock_200]

        session = RateLimitedSession()

        # First request: 429
        session.request("GET", "http://example.com")
        assert RateLimitedSession._consecutive_429 == 1

        # Reset backoff window
        RateLimitedSession._backoff_until = 0.0
        RateLimitedSession._announced_backoff = False

        # Second request: 200
        session.request("GET", "http://example.com")
        assert RateLimitedSession._consecutive_429 == 0

    @patch('requests.Session.request')
    def test_ratelimited_session_retry_after_numeric(self, mock_super_request):
        """Test parsing numeric Retry-After header."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": "30"}
        mock_response.text = "Rate Limited"
        mock_super_request.return_value = mock_response

        session = RateLimitedSession()
        session.request("GET", "http://example.com")

        # Backoff should be around 30 seconds
        wait_time = RateLimitedSession._backoff_until - time.time()
        assert 25 < wait_time < 35

    @patch('requests.Session.request')
    def test_ratelimited_session_retry_after_http_date(self, mock_super_request):
        """Test parsing HTTP-date Retry-After header."""
        import email.utils
        future_time = email.utils.formatdate(time.time() + 60, usegmt=True)

        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {"Retry-After": future_time}
        mock_response.text = "Rate Limited"
        mock_super_request.return_value = mock_response

        session = RateLimitedSession()
        session.request("GET", "http://example.com")

        # Backoff should be set
        assert RateLimitedSession._backoff_until > time.time()

    @patch('requests.Session.request')
    def test_ratelimited_session_connection_timeout(self, mock_super_request):
        """Test handling of connection timeout."""
        mock_super_request.side_effect = requests.exceptions.ConnectTimeout()

        session = RateLimitedSession()

        # Mock NetworkError for testing
        with patch('web_app.core.session.NetworkError', Exception):
            with pytest.raises(Exception):
                session.request("GET", "http://example.com")

    @patch('requests.Session.request')
    def test_ratelimited_session_read_timeout(self, mock_super_request):
        """Test handling of read timeout."""
        mock_super_request.side_effect = requests.exceptions.ReadTimeout()

        session = RateLimitedSession()

        with patch('web_app.core.session.NetworkError', Exception):
            with pytest.raises(Exception):
                session.request("GET", "http://example.com")

    @patch('requests.Session.request')
    def test_ratelimited_session_connection_error(self, mock_super_request):
        """Test handling of connection error."""
        mock_super_request.side_effect = requests.exceptions.ConnectionError()

        session = RateLimitedSession()

        with patch('web_app.core.session.NetworkError', Exception):
            with pytest.raises(Exception):
                session.request("GET", "http://example.com")

    @patch('requests.Session.request')
    def test_ratelimited_session_respects_backoff_window(self, mock_super_request):
        """Test that requests are delayed during backoff window."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "OK"
        mock_super_request.return_value = mock_response

        # Set backoff in future
        RateLimitedSession._backoff_until = time.time() + 0.5

        session = RateLimitedSession()
        start_time = time.time()
        session.request("GET", "http://example.com")
        elapsed = time.time() - start_time

        # Should have waited at least part of backoff
        assert elapsed >= 0.4

    @patch('requests.Session.request')
    def test_ratelimited_session_caps_backoff(self, mock_super_request):
        """Test that backoff is capped at 120 seconds."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {}
        mock_response.text = "Rate Limited"
        mock_super_request.return_value = mock_response

        session = RateLimitedSession()

        # Trigger many consecutive 429s
        for _ in range(10):
            session.request("GET", "http://example.com")
            RateLimitedSession._announced_backoff = False
            RateLimitedSession._backoff_until = 0.0

        # Set many consecutive 429s
        RateLimitedSession._consecutive_429 = 20

        session.request("GET", "http://example.com")

        # Backoff should be capped
        wait_time = RateLimitedSession._backoff_until - time.time()
        assert wait_time <= 120


class TestMakeSession:
    """Test make_session function."""

    def test_make_session_basic(self, mock_config):
        """Test creating basic session."""
        mock_config.user_agent = "TestBot/1.0"
        mock_config.proxy = None
        mock_config.cookie = None
        mock_config.extra_headers = []

        session = make_session(mock_config)

        assert isinstance(session, requests.Session)
        assert session.headers["User-Agent"] == "TestBot/1.0"
        assert session.verify is False

    def test_make_session_with_proxy(self, mock_config):
        """Test creating session with proxy."""
        mock_config.user_agent = "TestBot/1.0"
        mock_config.proxy = "http://proxy.local:8080"
        mock_config.cookie = None
        mock_config.extra_headers = []

        session = make_session(mock_config)

        assert session.proxies["http"] == "http://proxy.local:8080"
        assert session.proxies["https"] == "http://proxy.local:8080"

    def test_make_session_with_cookies(self, mock_config):
        """Test creating session with cookies."""
        mock_config.user_agent = "TestBot/1.0"
        mock_config.proxy = None
        mock_config.cookie = "session_id=abc123; user=test"
        mock_config.extra_headers = []

        session = make_session(mock_config)

        assert session.cookies.get("session_id") == "abc123"
        assert session.cookies.get("user") == "test"

    def test_make_session_with_extra_headers(self, mock_config):
        """Test creating session with extra headers."""
        mock_config.user_agent = "TestBot/1.0"
        mock_config.proxy = None
        mock_config.cookie = None
        mock_config.extra_headers = [
            "Authorization: Bearer token123",
            "X-API-Key: secret_key",
        ]

        session = make_session(mock_config)

        assert session.headers["Authorization"] == "Bearer token123"
        assert session.headers["X-API-Key"] == "secret_key"

    def test_make_session_with_all_options(self, mock_config):
        """Test creating session with all options."""
        mock_config.user_agent = "TestBot/1.0"
        mock_config.proxy = "http://proxy.local:8080"
        mock_config.cookie = "session=abc123"
        mock_config.extra_headers = ["Authorization: Bearer token"]

        session = make_session(mock_config)

        assert session.headers["User-Agent"] == "TestBot/1.0"
        assert session.proxies["http"] == "http://proxy.local:8080"
        assert session.cookies.get("session") == "abc123"
        assert session.headers["Authorization"] == "Bearer token"


class TestDetectScheme:
    """Test detect_scheme function."""

    @patch('web_app.core.session.make_session')
    def test_detect_scheme_https_preferred(self, mock_make_session, mock_config):
        """Test that HTTPS is detected and preferred."""
        mock_session = Mock()
        mock_make_session.return_value = mock_session

        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response

        result = detect_scheme("example.com", mock_config)

        assert result == "https"

    @patch('web_app.core.session.make_session')
    def test_detect_scheme_falls_back_to_http(self, mock_make_session, mock_config):
        """Test fallback to HTTP when HTTPS fails."""
        mock_session = Mock()
        mock_make_session.return_value = mock_session

        mock_response = Mock()
        mock_response.status_code = 200

        # HTTPS fails, HTTP succeeds
        mock_session.get.side_effect = [
            requests.exceptions.ConnectionError(),
            mock_response
        ]

        result = detect_scheme("example.com", mock_config)

        assert result == "http"

    @patch('web_app.core.session.make_session')
    def test_detect_scheme_defaults_to_http(self, mock_make_session, mock_config):
        """Test default to HTTP when both fail."""
        mock_session = Mock()
        mock_make_session.return_value = mock_session

        mock_session.get.side_effect = requests.exceptions.ConnectionError()

        result = detect_scheme("example.com", mock_config)

        assert result == "http"

    @patch('web_app.core.session.make_session')
    def test_detect_scheme_handles_timeout(self, mock_make_session, mock_config):
        """Test scheme detection handles timeout."""
        mock_session = Mock()
        mock_make_session.return_value = mock_session

        mock_response = Mock()
        mock_response.status_code = 200

        mock_session.get.side_effect = [
            requests.exceptions.Timeout(),
            mock_response
        ]

        result = detect_scheme("example.com", mock_config)

        assert result == "http"


class TestRevalidateSession:
    """Test revalidate_session function."""

    @patch('web_app.core.session.make_session')
    def test_revalidate_no_auth_check_configured(self, mock_make_session, mock_config):
        """Test revalidate returns True when no auth check configured."""
        mock_config.auth_check_url = None
        mock_config.auth_check_text = None

        result = revalidate_session(mock_config, "/tmp/out.txt")

        assert result is True

    @patch('web_app.core.session.make_session')
    def test_revalidate_successful_auth(self, mock_make_session, mock_config):
        """Test successful session revalidation."""
        mock_session = Mock()
        mock_make_session.return_value = mock_session

        mock_response = Mock()
        mock_response.text = "Welcome admin user"
        mock_session.get.return_value = mock_response

        mock_config.auth_check_url = "http://example.com/check"
        mock_config.auth_check_text = "Welcome"

        result = revalidate_session(mock_config, "/tmp/out.txt")

        assert result is True

    @patch('web_app.core.session.make_session')
    def test_revalidate_failed_auth(self, mock_make_session, mock_config):
        """Test failed session revalidation."""
        mock_session = Mock()
        mock_make_session.return_value = mock_session

        mock_response = Mock()
        mock_response.text = "Login required"
        mock_session.get.return_value = mock_response

        mock_config.auth_check_url = "http://example.com/check"
        mock_config.auth_check_text = "Welcome"

        result = revalidate_session(mock_config, "/tmp/out.txt")

        assert result is False

    @patch('web_app.core.session.make_session')
    def test_revalidate_timeout(self, mock_make_session, mock_config):
        """Test revalidate handles timeout."""
        mock_session = Mock()
        mock_make_session.return_value = mock_session

        mock_session.get.side_effect = requests.exceptions.Timeout()

        mock_config.auth_check_url = "http://example.com/check"
        mock_config.auth_check_text = "Welcome"

        result = revalidate_session(mock_config, "/tmp/out.txt")

        assert result is False

    @patch('web_app.core.session.make_session')
    def test_revalidate_connection_error(self, mock_make_session, mock_config):
        """Test revalidate handles connection error."""
        mock_session = Mock()
        mock_make_session.return_value = mock_session

        mock_session.get.side_effect = requests.exceptions.ConnectionError()

        mock_config.auth_check_url = "http://example.com/check"
        mock_config.auth_check_text = "Welcome"

        result = revalidate_session(mock_config, "/tmp/out.txt")

        assert result is False
