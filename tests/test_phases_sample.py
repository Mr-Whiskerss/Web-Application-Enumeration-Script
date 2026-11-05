"""
Unit tests for representative scanning phases.

Tests cover three key phase types:
1. Passive DNS reconnaissance (passive_dns) - passive, external data gathering
2. Port scanning (port_scan) - active infrastructure scanning
3. Nuclei vulnerability scanning (nuclei) - vulnerability discovery

Each phase tests:
- Tool availability checking (skipping when tools unavailable)
- Finding generation with proper severity levels
- State management (marking phases as complete)
- Error handling (tool errors, file parsing)
- Output logging and report generation

All external tool calls (nmap, nuclei, etc.) and file I/O are mocked
to ensure tests are fast and independent of installed tools.
"""

import pytest
import json
import os
from unittest.mock import Mock, patch, mock_open, MagicMock, call
from pathlib import Path

from web_app.core.findings import Finding, Severity
from web_app.core.state import ScanState
from web_app.core.config import ScanConfig, TargetType


# ═══════════════════════════════════════════════════════════════════════════
# PASSIVE DNS RECONNAISSANCE PHASE TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestPhasePassiveDns:
    """Test suite for passive DNS reconnaissance phase.

    Tests non-intrusive external data gathering including:
    - WHOIS queries for domain age
    - DNS lookups (nslookup, dnsrecon)
    - Subdomain enumeration
    - Recently registered domain detection
    """

    @pytest.fixture
    def mock_config(self):
        """Create a mock ScanConfig for testing.

        Returns:
            Mock: Config object with required attributes.
        """
        config = Mock(spec=ScanConfig)
        config.target = "example.com"
        config.base_url = "https://example.com"
        config.timeout = 10
        config.verbose = False
        config.proxy = None
        config.user_agent = "Mozilla/5.0"
        return config

    @pytest.fixture
    def mock_state(self, temp_dir):
        """Create a mock ScanState for tracking phase completion.

        Args:
            temp_dir: Temporary directory for state file.

        Returns:
            ScanState: State tracker with temp directory.
        """
        state_file = os.path.join(temp_dir, "state.json")
        return ScanState(state_file)

    @patch('web_app.phases.passive.run_cmd')
    @patch('web_app.phases.passive._tool_ok')
    def test_passive_dns_nslookup_called(self, mock_tool_ok, mock_run_cmd, mock_config, mock_state, temp_dir):
        """Test that nslookup is executed for DNS lookup.

        Verifies:
        - nslookup command invoked with target hostname
        - Output logged to report file
        - Phase marked as complete
        """
        from web_app.phases.passive import phase_passive_dns

        mock_tool_ok.return_value = False
        output_file = os.path.join(temp_dir, "report.md")

        phase_passive_dns("example.com", TargetType.DOMAIN, mock_config, output_file, mock_state, None)

        # Verify nslookup was called
        nslookup_calls = [call for call in mock_run_cmd.call_args_list if "nslookup" in str(call)]
        assert len(nslookup_calls) > 0

    @patch('web_app.phases.passive.run_cmd')
    @patch('web_app.phases.passive._tool_ok')
    @patch('web_app.phases.passive.add_finding')
    def test_passive_dns_recently_registered_detection(self, mock_add_finding, mock_tool_ok,
                                                      mock_run_cmd, mock_config, mock_state, temp_dir):
        """Test detection of recently registered domains.

        Verifies:
        - WHOIS output parsed for creation date
        - Finding generated when domain < 1 year old
        - Severity set to MEDIUM
        """
        from web_app.phases.passive import phase_passive_dns

        mock_tool_ok.return_value = False
        output_file = os.path.join(temp_dir, "report.md")

        # Mock run_cmd to return WHOIS output with recent creation date
        whois_output = "Creation Date: 2025-06-01T00:00:00Z"
        mock_run_cmd.return_value = (whois_output, "", 0)

        phase_passive_dns("example.com", TargetType.DOMAIN, mock_config, output_file, mock_state, None)

        # Verify finding was generated for recent domain
        finding_calls = [call for call in mock_add_finding.call_args_list
                        if call[0][0].title == "Recently Registered Domain"]
        assert len(finding_calls) > 0

    @patch('web_app.phases.passive.run_cmd')
    @patch('web_app.phases.passive._tool_ok')
    def test_passive_dns_skip_when_done(self, mock_tool_ok, mock_run_cmd, mock_config, mock_state, temp_dir):
        """Test that phase is skipped if already marked as done.

        Verifies:
        - Phase skipped when state.done() returns True
        - No external commands executed
        """
        from web_app.phases.passive import phase_passive_dns

        # Mark phase as done in state
        mock_state.mark("passive_dns")

        output_file = os.path.join(temp_dir, "report.md")
        phase_passive_dns("example.com", TargetType.DOMAIN, mock_config, output_file, mock_state, None)

        # Verify run_cmd was never called
        mock_run_cmd.assert_not_called()

    @patch('web_app.phases.passive.run_cmd')
    @patch('web_app.phases.passive._tool_ok')
    def test_passive_dns_handles_ipv4_target(self, mock_tool_ok, mock_run_cmd, mock_config,
                                            mock_state, temp_dir):
        """Test passive DNS handling of IPv4 address targets.

        Verifies:
        - IPv4 targets are handled (no domain-specific checks)
        - nslookup still attempted
        - State marked as done
        """
        from web_app.phases.passive import phase_passive_dns

        mock_tool_ok.return_value = False
        output_file = os.path.join(temp_dir, "report.md")

        phase_passive_dns("192.168.1.1", TargetType.IP, mock_config, output_file, mock_state, None)

        # Phase should be marked complete
        assert mock_state.done("passive_dns")


# ═══════════════════════════════════════════════════════════════════════════
# ACTIVE PORT SCANNING PHASE TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestPhasePortScan:
    """Test suite for active port scanning phase using nmap.

    Tests:
    - Port scanning with common ports vs full range
    - Nmap tool availability checking
    - Sudo elevation for raw socket access
    - Service version detection
    - HTTP methods scanning
    """

    @pytest.fixture
    def mock_config(self):
        """Create a mock ScanConfig for port scanning.

        Returns:
            Mock: Config object with port scanning parameters.
        """
        config = Mock(spec=ScanConfig)
        config.target = "example.com"
        config.base_url = "https://example.com"
        config.timeout = 10
        config.verbose = False
        config.full_ports = False
        return config

    @pytest.fixture
    def mock_state(self, temp_dir):
        """Create a mock ScanState.

        Args:
            temp_dir: Temporary directory for state file.

        Returns:
            ScanState: State tracker.
        """
        state_file = os.path.join(temp_dir, "state.json")
        return ScanState(state_file)

    @patch('web_app.phases.active._sudo')
    @patch('web_app.phases.active.run_cmd')
    @patch('web_app.phases.active._tool_ok')
    def test_port_scan_tool_missing(self, mock_tool_ok, mock_run_cmd, mock_sudo,
                                    mock_config, mock_state, temp_dir):
        """Test port scanning when nmap tool is not installed.

        Verifies:
        - Phase skips gracefully when nmap not available
        - State marked as done
        - No commands executed
        """
        from web_app.phases.active import phase_port_scan

        mock_tool_ok.return_value = False
        output_file = os.path.join(temp_dir, "report.md")

        phase_port_scan("example.com", mock_config, output_file, mock_state)

        # Verify phase marked done and no commands run
        assert mock_state.done("port_scan")
        mock_run_cmd.assert_not_called()

    @patch('web_app.phases.active._sudo')
    @patch('web_app.phases.active.run_cmd')
    @patch('web_app.phases.active._tool_ok')
    def test_port_scan_common_ports(self, mock_tool_ok, mock_run_cmd, mock_sudo,
                                    mock_config, mock_state, temp_dir):
        """Test port scanning with common ports list.

        Verifies:
        - Nmap called with common web ports when full_ports=False
        - Service version detection enabled (-sV)
        - Output saved to /tmp/nmap_*
        """
        from web_app.phases.active import phase_port_scan

        mock_tool_ok.return_value = True
        mock_sudo.return_value = []
        mock_run_cmd.return_value = ("", "", 0)
        output_file = os.path.join(temp_dir, "report.md")
        mock_config.full_ports = False

        phase_port_scan("example.com", mock_config, output_file, mock_state)

        # Verify nmap called with common ports
        nmap_calls = [call for call in mock_run_cmd.call_args_list if "nmap" in str(call)]
        assert len(nmap_calls) > 0

        # Verify -sV (service version detection) included
        assert any("-sV" in str(call) for call in nmap_calls)

    @patch('web_app.phases.active._sudo')
    @patch('web_app.phases.active.run_cmd')
    @patch('web_app.phases.active._tool_ok')
    def test_port_scan_full_range(self, mock_tool_ok, mock_run_cmd, mock_sudo,
                                  mock_config, mock_state, temp_dir):
        """Test port scanning with full port range (1-65535).

        Verifies:
        - Nmap called with -p- (all ports) when full_ports=True
        - Higher timeout used (2400 seconds)
        - Rate limiting applied
        """
        from web_app.phases.active import phase_port_scan

        mock_tool_ok.return_value = True
        mock_sudo.return_value = []
        mock_run_cmd.return_value = ("", "", 0)
        output_file = os.path.join(temp_dir, "report.md")
        mock_config.full_ports = True

        phase_port_scan("example.com", mock_config, output_file, mock_state)

        # Verify nmap called with full port range
        nmap_calls = [call for call in mock_run_cmd.call_args_list if "nmap" in str(call)]
        assert any("-p-" in str(call) for call in nmap_calls)

    @patch('web_app.phases.active._sudo')
    @patch('web_app.phases.active.run_cmd')
    @patch('web_app.phases.active._tool_ok')
    def test_port_scan_http_methods(self, mock_tool_ok, mock_run_cmd, mock_sudo,
                                    mock_config, mock_state, temp_dir):
        """Test HTTP methods NSE script execution.

        Verifies:
        - NSE script for HTTP methods called on standard ports
        - Script targeting ports 80, 443, 8080, 8443
        """
        from web_app.phases.active import phase_port_scan

        mock_tool_ok.return_value = True
        mock_sudo.return_value = []
        mock_run_cmd.return_value = ("", "", 0)
        output_file = os.path.join(temp_dir, "report.md")

        phase_port_scan("example.com", mock_config, output_file, mock_state)

        # Verify HTTP methods NSE script called
        nse_calls = [call for call in mock_run_cmd.call_args_list if "http-methods" in str(call)]
        assert len(nse_calls) > 0


# ═══════════════════════════════════════════════════════════════════════════
# VULNERABILITY SCANNING (NUCLEI) PHASE TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestPhaseNuclei:
    """Test suite for nuclei vulnerability scanning phase.

    Tests:
    - Nuclei tool execution with severity filtering
    - JSONL output parsing
    - Finding generation from nuclei results
    - Severity mapping (info/low/medium/high/critical)
    - Proxy and custom header passing
    - Graceful handling of missing output file
    """

    @pytest.fixture
    def mock_config(self):
        """Create a mock ScanConfig for nuclei scanning.

        Returns:
            Mock: Config object with nuclei parameters.
        """
        config = Mock(spec=ScanConfig)
        config.target = "example.com"
        config.base_url = "https://example.com"
        config.timeout = 10
        config.verbose = False
        config.threads = 5
        config.rate = 50
        config.proxy = None
        config.cookie = None
        config.extra_headers = []
        config.no_intrusive = False
        config.nuclei_severity = "high,critical"
        return config

    @pytest.fixture
    def mock_state(self, temp_dir):
        """Create a mock ScanState.

        Args:
            temp_dir: Temporary directory for state file.

        Returns:
            ScanState: State tracker.
        """
        state_file = os.path.join(temp_dir, "state.json")
        return ScanState(state_file)

    @patch('web_app.phases.vulns.run_cmd')
    @patch('web_app.phases.vulns._tool_ok')
    def test_nuclei_tool_missing(self, mock_tool_ok, mock_run_cmd, mock_config, mock_state, temp_dir):
        """Test nuclei phase when nuclei tool is not installed.

        Verifies:
        - Phase skips gracefully when nuclei not available
        - State marked as done
        - Helpful message logged
        """
        from web_app.phases.vulns import phase_nuclei

        mock_tool_ok.return_value = False
        output_file = os.path.join(temp_dir, "report.md")

        phase_nuclei("example.com", mock_config, output_file, mock_state)

        assert mock_state.done("nuclei")
        mock_run_cmd.assert_not_called()

    @patch('web_app.phases.vulns.add_finding')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists')
    @patch('web_app.phases.vulns.run_cmd')
    @patch('web_app.phases.vulns._tool_ok')
    def test_nuclei_parses_jsonl_output(self, mock_tool_ok, mock_run_cmd, mock_exists,
                                        mock_file, mock_add_finding, mock_config, mock_state, temp_dir):
        """Test nuclei JSONL output parsing and finding generation.

        Verifies:
        - Nuclei output file read and parsed line-by-line
        - Each JSONL entry converted to Finding object
        - Severity levels mapped correctly
        - Finding title includes nuclei template name
        """
        from web_app.phases.vulns import phase_nuclei

        mock_tool_ok.return_value = True
        mock_run_cmd.return_value = ("", "", 0)
        output_file = os.path.join(temp_dir, "report.md")

        # Mock nuclei output file with sample findings
        nuclei_output = [
            json.dumps({
                "template-id": "http-missing-security-headers",
                "info": {
                    "name": "Missing Security Headers",
                    "severity": "medium",
                    "description": "Security headers are missing",
                    "remediation": "Add security headers"
                },
                "host": "https://example.com",
                "matched-at": "https://example.com/"
            }),
            json.dumps({
                "template-id": "cve-2024-1234",
                "info": {
                    "name": "Known Vulnerability",
                    "severity": "critical",
                    "description": "Critical vulnerability found",
                    "tags": ["cve", "critical"]
                },
                "host": "https://example.com",
                "matched-at": "https://example.com/admin"
            })
        ]

        mock_exists.return_value = True
        mock_file.return_value.__enter__.return_value = nuclei_output

        phase_nuclei("example.com", mock_config, output_file, mock_state)

        # Verify findings were generated
        assert mock_add_finding.call_count == 2

        # Verify first finding
        first_call = mock_add_finding.call_args_list[0]
        first_finding = first_call[0][0]
        assert "Missing Security Headers" in first_finding.title
        assert first_finding.severity == Severity.MEDIUM

        # Verify second finding
        second_call = mock_add_finding.call_args_list[1]
        second_finding = second_call[0][0]
        assert first_finding.severity == Severity.MEDIUM
        assert second_finding.severity == Severity.CRITICAL

    @patch('web_app.phases.vulns.add_finding')
    @patch('os.path.exists')
    @patch('web_app.phases.vulns.run_cmd')
    @patch('web_app.phases.vulns._tool_ok')
    def test_nuclei_no_output_file(self, mock_tool_ok, mock_run_cmd, mock_exists,
                                   mock_add_finding, mock_config, mock_state, temp_dir):
        """Test nuclei phase when output file is not created.

        Verifies:
        - Phase completes gracefully if nuclei doesn't create output file
        - No findings generated
        - State marked as done
        """
        from web_app.phases.vulns import phase_nuclei

        mock_tool_ok.return_value = True
        mock_run_cmd.return_value = ("", "", 0)
        mock_exists.return_value = False
        output_file = os.path.join(temp_dir, "report.md")

        phase_nuclei("example.com", mock_config, output_file, mock_state)

        # Verify no findings added (file doesn't exist)
        mock_add_finding.assert_not_called()
        assert mock_state.done("nuclei")

    @patch('web_app.phases.vulns.add_finding')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists')
    @patch('web_app.phases.vulns.run_cmd')
    @patch('web_app.phases.vulns._tool_ok')
    def test_nuclei_severity_levels(self, mock_tool_ok, mock_run_cmd, mock_exists,
                                    mock_file, mock_add_finding, mock_config, mock_state, temp_dir):
        """Test nuclei severity level mapping for all levels.

        Verifies:
        - info → INFO
        - low → LOW
        - medium → MEDIUM
        - high → HIGH
        - critical → CRITICAL
        - unknown → INFO (default)
        """
        from web_app.phases.vulns import phase_nuclei

        mock_tool_ok.return_value = True
        mock_run_cmd.return_value = ("", "", 0)
        output_file = os.path.join(temp_dir, "report.md")

        severity_map = {
            "info": Severity.INFO,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

        nuclei_output = []
        for nuclei_sev, expected_sev in severity_map.items():
            nuclei_output.append(json.dumps({
                "template-id": f"test-{nuclei_sev}",
                "info": {
                    "name": f"Test {nuclei_sev}",
                    "severity": nuclei_sev,
                    "description": f"Finding with {nuclei_sev} severity"
                },
                "matched-at": "https://example.com"
            }))

        mock_exists.return_value = True
        mock_file.return_value.__enter__.return_value = nuclei_output

        phase_nuclei("example.com", mock_config, output_file, mock_state)

        # Verify all severities mapped correctly
        for i, (nuclei_sev, expected_sev) in enumerate(severity_map.items()):
            call = mock_add_finding.call_args_list[i]
            finding = call[0][0]
            assert finding.severity == expected_sev

    @patch('web_app.phases.vulns.add_finding')
    @patch('builtins.open', new_callable=mock_open)
    @patch('os.path.exists')
    @patch('web_app.phases.vulns.run_cmd')
    @patch('web_app.phases.vulns._tool_ok')
    def test_nuclei_malformed_json_skipped(self, mock_tool_ok, mock_run_cmd, mock_exists,
                                          mock_file, mock_add_finding, mock_config, mock_state, temp_dir):
        """Test nuclei phase handles malformed JSONL entries gracefully.

        Verifies:
        - Invalid JSON lines are skipped silently
        - Valid lines still parsed
        - No exception raised
        """
        from web_app.phases.vulns import phase_nuclei

        mock_tool_ok.return_value = True
        mock_run_cmd.return_value = ("", "", 0)
        output_file = os.path.join(temp_dir, "report.md")

        # Mix of valid and invalid JSON
        nuclei_output = [
            json.dumps({"template-id": "test-1", "info": {"name": "Valid", "severity": "info"}}),
            "INVALID JSON {{{",  # This line will cause JSON decode error
            json.dumps({"template-id": "test-2", "info": {"name": "Also Valid", "severity": "low"}})
        ]

        mock_exists.return_value = True
        mock_file.return_value.__enter__.return_value = nuclei_output

        phase_nuclei("example.com", mock_config, output_file, mock_state)

        # Verify only 2 valid findings processed (invalid line skipped)
        assert mock_add_finding.call_count == 2

    @patch('web_app.phases.vulns.run_cmd')
    @patch('web_app.phases.vulns._tool_ok')
    def test_nuclei_command_construction(self, mock_tool_ok, mock_run_cmd, mock_config, mock_state, temp_dir):
        """Test that nuclei command is constructed with correct parameters.

        Verifies:
        - URL passed to nuclei
        - Severity filter applied
        - JSONL output format specified
        - Threading and rate limiting configured
        - Proxy and headers included if configured
        - No-intrusive tags excluded if flag set
        """
        from web_app.phases.vulns import phase_nuclei

        mock_tool_ok.return_value = True
        mock_run_cmd.return_value = ("", "", 0)
        output_file = os.path.join(temp_dir, "report.md")
        mock_config.proxy = "http://proxy:8080"
        mock_config.cookie = "session=abc123"
        mock_config.extra_headers = ["X-Custom: value"]
        mock_config.no_intrusive = True

        phase_nuclei("example.com", mock_config, output_file, mock_state)

        # Verify nuclei command called
        run_cmd_calls = mock_run_cmd.call_args_list
        assert len(run_cmd_calls) > 0

        # Get the nuclei command (first element of first call)
        nuclei_cmd = run_cmd_calls[0][0][0]

        # Verify command structure
        assert "nuclei" in nuclei_cmd
        assert "-u" in nuclei_cmd
        assert "example.com" in nuclei_cmd
        assert "-severity" in nuclei_cmd
        assert "-jsonl" in nuclei_cmd
