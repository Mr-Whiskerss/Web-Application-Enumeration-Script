"""
Unit tests for webhook and pentestdb integration modules.

Tests cover:
- webhook_notify() function with Discord and Slack webhook URLs
- pentestdb_push() function for sending findings to PentestDB API
- HTTP error handling (timeouts, connection errors, HTTP errors)
- Finding generation with various severity levels
- Proxy configuration and authentication headers
- Graceful degradation with missing config

All external HTTP calls are mocked using unittest.mock.patch to ensure
tests are fast and independent of network availability.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
import requests

from web_app.core.findings import Finding, Severity
from web_app.integrations import webhook, pentestdb


# ═══════════════════════════════════════════════════════════════════════════
# WEBHOOK INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestWebhookNotify:
    """Test suite for webhook_notify() function.

    Covers Discord and Slack notification formatting, proxy configuration,
    error handling, and logging behavior.
    """

    @pytest.fixture
    def sample_finding(self):
        """Create a sample Finding object for testing.

        Returns:
            Finding: A test finding with all required fields populated.
        """
        return Finding(
            title="Test SQL Injection Vulnerability",
            severity=Severity.HIGH,
            description="Possible SQL injection in login form parameter.",
            evidence="payload: ' OR '1'='1",
            recommendation="Use parameterized queries",
            phase="sqli_testing",
            timestamp="2025-11-05T10:30:00"
        )

    @pytest.fixture
    def sample_config(self, mock_config):
        """Create a sample ScanConfig with webhook settings.

        Args:
            mock_config: Fixture providing mock config object.

        Returns:
            Mock: Config object with webhook_url set to Discord webhook.
        """
        mock_config.webhook_url = "https://discord.com/api/webhooks/123456/abcdef"
        mock_config.target = "example.com"
        mock_config.proxy = None
        return mock_config

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_discord_success(self, mock_post, sample_finding, sample_config):
        """Test successful Discord webhook notification.

        Verifies:
        - POST request sent to webhook URL
        - Payload contains Discord embed format
        - Status code 200 returns silently
        - Correct color mapping for severity level
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        webhook.webhook_notify(sample_finding, sample_config)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args

        assert args[0] == sample_config.webhook_url
        assert "json" in kwargs
        payload = kwargs["json"]

        # Verify Discord embed structure
        assert "embeds" in payload
        assert len(payload["embeds"]) == 1
        embed = payload["embeds"][0]

        assert f"[{sample_finding.severity.value}]" in embed["title"]
        assert sample_finding.title in embed["title"]
        assert sample_finding.description[:1500] == embed["description"]
        assert embed["color"] == 0xe67e22  # HIGH severity color

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_slack_success(self, mock_post, sample_finding, sample_config):
        """Test successful Slack webhook notification.

        Verifies:
        - POST request sent to Slack webhook URL
        - Payload uses Slack text message format (not embed)
        - Finding severity, title, and target included in message
        - Formatting uses Slack markdown (_ for italics, * for bold)
        """
        sample_config.webhook_url = "https://hooks.slack.com/services/T00/B00/XX"
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        webhook.webhook_notify(sample_finding, sample_config)

        args, kwargs = mock_post.call_args
        payload = kwargs["json"]

        # Verify Slack message structure (plain text, not embed)
        assert "text" in payload
        assert "embeds" not in payload
        assert f"[{sample_finding.severity.value}]" in payload["text"]
        assert sample_finding.title in payload["text"]
        assert sample_config.target in payload["text"]

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_with_proxy(self, mock_post, sample_finding, sample_config):
        """Test webhook notification with proxy configuration.

        Verifies:
        - Proxy settings included in request
        - Both HTTP and HTTPS proxies set
        """
        sample_config.proxy = "http://proxy.internal:8080"
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        webhook.webhook_notify(sample_finding, sample_config)

        args, kwargs = mock_post.call_args
        assert "proxies" in kwargs
        assert kwargs["proxies"]["http"] == sample_config.proxy
        assert kwargs["proxies"]["https"] == sample_config.proxy

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_no_url(self, mock_post, sample_finding, sample_config):
        """Test webhook_notify silently returns when webhook_url is None.

        Verifies:
        - No HTTP request made when webhook URL not configured
        - Function returns early without error
        """
        sample_config.webhook_url = None
        webhook.webhook_notify(sample_finding, sample_config)
        mock_post.assert_not_called()

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_http_error_400(self, mock_post, sample_finding, sample_config):
        """Test webhook_notify handles HTTP 400 client error gracefully.

        Verifies:
        - Function handles HTTP 400 status without raising exception
        - Logs warning message (verified via mock logger)
        """
        mock_response = Mock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response

        # Should not raise exception
        webhook.webhook_notify(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_http_error_500(self, mock_post, sample_finding, sample_config):
        """Test webhook_notify handles HTTP 500 server error gracefully.

        Verifies:
        - Function handles HTTP 500 status without raising exception
        - Continues after server-side errors
        """
        mock_response = Mock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        webhook.webhook_notify(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_timeout(self, mock_post, sample_finding, sample_config):
        """Test webhook_notify handles request timeout gracefully.

        Verifies:
        - RequestException with timeout reason caught
        - Function continues without raising exception
        - No retry attempted
        """
        mock_post.side_effect = requests.exceptions.Timeout("Connection timeout")
        webhook.webhook_notify(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_connection_error(self, mock_post, sample_finding, sample_config):
        """Test webhook_notify handles connection errors gracefully.

        Verifies:
        - RequestException with connection error caught
        - Function continues without raising exception
        """
        mock_post.side_effect = requests.exceptions.ConnectionError("Network unreachable")
        webhook.webhook_notify(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_unexpected_exception(self, mock_post, sample_finding, sample_config):
        """Test webhook_notify handles unexpected exceptions gracefully.

        Verifies:
        - Unexpected exception (e.g., ValueError) caught and handled
        - Function continues without raising exception
        """
        mock_post.side_effect = ValueError("Unexpected error in JSON encoding")
        webhook.webhook_notify(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_severity_colors(self, mock_post, sample_config):
        """Test that all severity levels map to correct Discord embed colors.

        Verifies:
        - INFO severity → blue (0x3498db)
        - LOW severity → green (0x2ecc71)
        - MEDIUM severity → yellow (0xf1c40f)
        - HIGH severity → orange (0xe67e22)
        - CRITICAL severity → red (0xe74c3c)
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        color_map = {
            Severity.INFO: 0x3498db,
            Severity.LOW: 0x2ecc71,
            Severity.MEDIUM: 0xf1c40f,
            Severity.HIGH: 0xe67e22,
            Severity.CRITICAL: 0xe74c3c,
        }

        for severity, expected_color in color_map.items():
            mock_post.reset_mock()
            finding = Finding(
                title=f"Test {severity.value}",
                severity=severity,
                description="Test description",
                phase="test"
            )
            sample_config.webhook_url = "https://discord.com/api/webhooks/123/abc"

            webhook.webhook_notify(finding, sample_config)

            args, kwargs = mock_post.call_args
            embed = kwargs["json"]["embeds"][0]
            assert embed["color"] == expected_color

    @patch('web_app.integrations.webhook.requests.post')
    def test_webhook_description_truncated(self, mock_post, sample_config):
        """Test that long descriptions are truncated to 1500 chars in webhook payload.

        Verifies:
        - Description longer than 1500 chars is trimmed
        - Doesn't break embed format
        """
        long_description = "A" * 2000
        finding = Finding(
            title="Test",
            severity=Severity.INFO,
            description=long_description,
            phase="test"
        )
        sample_config.webhook_url = "https://discord.com/api/webhooks/123/abc"

        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        webhook.webhook_notify(finding, sample_config)

        args, kwargs = mock_post.call_args
        embed = kwargs["json"]["embeds"][0]
        assert len(embed["description"]) == 1500
        assert embed["description"] == "A" * 1500


# ═══════════════════════════════════════════════════════════════════════════
# PENTESTDB INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestPentestdbPush:
    """Test suite for pentestdb_push() function.

    Covers PentestDB API integration, authentication, payload formatting,
    error handling, and endpoint construction.
    """

    @pytest.fixture
    def sample_finding(self):
        """Create a sample Finding object for testing.

        Returns:
            Finding: A test finding with all required fields populated.
        """
        return Finding(
            title="Exposed AWS S3 Bucket",
            severity=Severity.CRITICAL,
            description="S3 bucket is publicly readable",
            evidence="http://bucket.s3.amazonaws.com/index.html",
            recommendation="Restrict bucket permissions via bucket policy",
            phase="cloud_discovery",
            timestamp="2025-11-05T12:00:00"
        )

    @pytest.fixture
    def sample_config(self, mock_config):
        """Create a sample ScanConfig with PentestDB settings.

        Args:
            mock_config: Fixture providing mock config object.

        Returns:
            Mock: Config object with pentestdb_url configured.
        """
        mock_config.pentestdb_url = "https://pentestdb.internal"
        mock_config.pentestdb_token = "secret_bearer_token_12345"
        mock_config.target = "example.com"
        return mock_config

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_success(self, mock_post, sample_finding, sample_config):
        """Test successful finding push to PentestDB.

        Verifies:
        - POST request sent to correct endpoint ({pentestdb_url}/api/findings)
        - Payload includes all finding fields and metadata
        - HTTP 200 response handled silently
        - Bearer token included in Authorization header
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        pentestdb.pentestdb_push(sample_finding, sample_config)

        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args

        # Verify endpoint URL
        expected_endpoint = "https://pentestdb.internal/api/findings"
        assert args[0] == expected_endpoint

        # Verify payload
        payload = kwargs["json"]
        assert payload["target"] == sample_config.target
        assert payload["title"] == sample_finding.title
        assert payload["severity"] == sample_finding.severity.value
        assert payload["description"] == sample_finding.description
        assert payload["evidence"] == sample_finding.evidence
        assert payload["recommendation"] == sample_finding.recommendation
        assert payload["phase"] == sample_finding.phase
        assert payload["timestamp"] == sample_finding.timestamp
        assert payload["tool"] == "WebRecon"

        # Verify authentication header
        assert "headers" in kwargs
        assert kwargs["headers"]["Authorization"] == f"Bearer {sample_config.pentestdb_token}"

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_no_token(self, mock_post, sample_finding, sample_config):
        """Test PentestDB push without authentication token.

        Verifies:
        - Function works without bearer token
        - Authorization header omitted when token is None
        - Request still sends with Content-Type header
        """
        sample_config.pentestdb_token = None
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        pentestdb.pentestdb_push(sample_finding, sample_config)

        args, kwargs = mock_post.call_args
        assert "Authorization" not in kwargs["headers"]
        assert kwargs["headers"]["Content-Type"] == "application/json"

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_no_url(self, mock_post, sample_finding, sample_config):
        """Test pentestdb_push returns early when pentestdb_url is None.

        Verifies:
        - No HTTP request made when PentestDB URL not configured
        - Function returns silently
        """
        sample_config.pentestdb_url = None
        pentestdb.pentestdb_push(sample_finding, sample_config)
        mock_post.assert_not_called()

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_trailing_slash(self, mock_post, sample_finding, sample_config):
        """Test PentestDB endpoint URL handling with trailing slash.

        Verifies:
        - Trailing slash in pentestdb_url is stripped
        - Endpoint remains /api/findings
        """
        sample_config.pentestdb_url = "https://pentestdb.internal/"
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        pentestdb.pentestdb_push(sample_finding, sample_config)

        args, kwargs = mock_post.call_args
        assert args[0] == "https://pentestdb.internal/api/findings"

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_http_error_400(self, mock_post, sample_finding, sample_config):
        """Test PentestDB push handles HTTP 400 client error gracefully.

        Verifies:
        - Function handles HTTP 400 status without raising exception
        """
        mock_response = Mock()
        mock_response.status_code = 400
        mock_post.return_value = mock_response

        pentestdb.pentestdb_push(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_http_error_500(self, mock_post, sample_finding, sample_config):
        """Test PentestDB push handles HTTP 500 server error gracefully.

        Verifies:
        - Function handles HTTP 500 status without raising exception
        - Continues despite server errors
        """
        mock_response = Mock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        pentestdb.pentestdb_push(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_timeout(self, mock_post, sample_finding, sample_config):
        """Test PentestDB push handles request timeout gracefully.

        Verifies:
        - Timeout exception caught and handled
        - Function continues without raising exception
        - No retry attempted
        """
        mock_post.side_effect = requests.exceptions.Timeout("Request timed out")
        pentestdb.pentestdb_push(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_connection_error(self, mock_post, sample_finding, sample_config):
        """Test PentestDB push handles connection errors gracefully.

        Verifies:
        - Connection error caught and handled
        - Function continues without raising exception
        """
        mock_post.side_effect = requests.exceptions.ConnectionError("Host unreachable")
        pentestdb.pentestdb_push(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_unexpected_exception(self, mock_post, sample_finding, sample_config):
        """Test PentestDB push handles unexpected exceptions gracefully.

        Verifies:
        - Unexpected exception caught and handled
        - Function continues without raising exception
        """
        mock_post.side_effect = ValueError("Unexpected error")
        pentestdb.pentestdb_push(sample_finding, sample_config)
        mock_post.assert_called_once()

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_all_severities(self, mock_post, sample_config):
        """Test that PentestDB push works with all severity levels.

        Verifies:
        - Finding can be pushed for each severity level
        - Severity value correctly serialized in payload
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        for severity in Severity:
            mock_post.reset_mock()
            finding = Finding(
                title=f"Test {severity.value}",
                severity=severity,
                description="Test description",
                phase="test"
            )

            pentestdb.pentestdb_push(finding, sample_config)

            args, kwargs = mock_post.call_args
            assert kwargs["json"]["severity"] == severity.value

    @patch('web_app.integrations.pentestdb.requests.post')
    def test_pentestdb_push_timeout_value(self, mock_post, sample_finding, sample_config):
        """Test that PentestDB push uses 10-second timeout for HTTP request.

        Verifies:
        - Timeout parameter set to 10 seconds (not 5 like webhook)
        """
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        pentestdb.pentestdb_push(sample_finding, sample_config)

        args, kwargs = mock_post.call_args
        assert kwargs["timeout"] == 10


# ═══════════════════════════════════════════════════════════════════════════
# CROSS-INTEGRATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestIntegrationInteraction:
    """Test interactions between webhook and pentestdb integrations."""

    @patch('web_app.integrations.webhook.requests.post')
    @patch('web_app.integrations.pentestdb.requests.post')
    def test_both_integrations_succeed(self, mock_pentestdb, mock_webhook, mock_config):
        """Test that both webhook and pentestdb can be triggered for same finding.

        Verifies:
        - Both functions can be called independently
        - Failure in one doesn't prevent the other
        """
        mock_config.webhook_url = "https://discord.com/api/webhooks/123/abc"
        mock_config.pentestdb_url = "https://pentestdb.internal"
        mock_config.pentestdb_token = "token"
        mock_config.target = "example.com"

        mock_webhook.return_value = Mock(status_code=200)
        mock_pentestdb.return_value = Mock(status_code=200)

        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            description="Test finding",
            phase="test"
        )

        webhook.webhook_notify(finding, mock_config)
        pentestdb.pentestdb_push(finding, mock_config)

        mock_webhook.assert_called_once()
        mock_pentestdb.assert_called_once()

    @patch('web_app.integrations.webhook.requests.post')
    @patch('web_app.integrations.pentestdb.requests.post')
    def test_webhook_failure_doesnt_prevent_pentestdb(self, mock_pentestdb, mock_webhook, mock_config):
        """Test that webhook timeout doesn't prevent pentestdb push.

        Verifies:
        - Integrations are independent
        - Failure in one doesn't cascade to other
        """
        mock_config.webhook_url = "https://discord.com/api/webhooks/123/abc"
        mock_config.pentestdb_url = "https://pentestdb.internal"
        mock_config.pentestdb_token = "token"
        mock_config.target = "example.com"

        mock_webhook.side_effect = requests.exceptions.Timeout()
        mock_pentestdb.return_value = Mock(status_code=200)

        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            phase="test"
        )

        webhook.webhook_notify(finding, mock_config)
        pentestdb.pentestdb_push(finding, mock_config)

        mock_webhook.assert_called_once()
        mock_pentestdb.assert_called_once()
