"""
Comprehensive unit tests for web_app.utils.subprocess_runner module.

Tests cover:
  - run_cmd(): Command execution with success/failure/timeout/error cases
  - _log(): Thread-safe file logging
  - ToolNotFound exception handling
  - Thread safety and concurrent logging
"""

import pytest
import subprocess
import tempfile
import os
import threading
import time
from unittest.mock import patch, MagicMock, call
from dataclasses import dataclass

from web_app.utils.subprocess_runner import run_cmd, _log, ToolNotFound


# ═════════════════════════════════════════════════════════════════════════════
# FIXTURES
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class MockConfig:
    """Mock configuration object for testing."""
    verbose: bool = False


@pytest.fixture
def temp_output_file():
    """Create temporary output file for logging."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.md') as f:
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.unlink(temp_path)


# ═════════════════════════════════════════════════════════════════════════════
# TEST: _log() - Thread-safe file logging
# ═════════════════════════════════════════════════════════════════════════════

class TestLog:
    """Test _log() function for thread-safe logging."""

    def test_log_appends_to_file(self, temp_output_file):
        """_log() appends message to file."""
        _log(temp_output_file, "Test message")
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Test message" in content

    def test_log_adds_newline(self, temp_output_file):
        """_log() adds newline after each message."""
        _log(temp_output_file, "Line 1")
        _log(temp_output_file, "Line 2")
        with open(temp_output_file, 'r') as f:
            lines = f.readlines()
        assert len(lines) == 2
        assert lines[0].strip() == "Line 1"
        assert lines[1].strip() == "Line 2"

    def test_log_multiple_calls_append(self, temp_output_file):
        """_log() appends to existing content."""
        _log(temp_output_file, "First")
        _log(temp_output_file, "Second")
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "First" in content
        assert "Second" in content
        assert content.index("First") < content.index("Second")

    def test_log_empty_message(self, temp_output_file):
        """_log() handles empty messages."""
        _log(temp_output_file, "")
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert content == "\n"

    def test_log_multiline_message(self, temp_output_file):
        """_log() handles multiline messages."""
        msg = "Line 1\nLine 2\nLine 3"
        _log(temp_output_file, msg)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Line 1" in content
        assert "Line 2" in content
        assert "Line 3" in content

    def test_log_special_characters(self, temp_output_file):
        """_log() preserves special characters."""
        msg = "Special: !@#$%^&*()_+-=[]{}|;:',.<>?/`~"
        _log(temp_output_file, msg)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert msg in content

    def test_log_unicode_characters(self, temp_output_file):
        """_log() handles Unicode characters."""
        msg = "Unicode: 你好世界 🌍 Ω"
        _log(temp_output_file, msg)
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert msg in content

    def test_log_thread_safety(self, temp_output_file):
        """_log() is thread-safe with concurrent writes."""
        def write_logs(thread_id, count):
            for i in range(count):
                _log(temp_output_file, f"Thread {thread_id} Message {i}")

        threads = []
        for i in range(5):
            t = threading.Thread(target=write_logs, args=(i, 10))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        with open(temp_output_file, 'r') as f:
            lines = f.readlines()

        # Should have 5 threads * 10 messages = 50 lines
        assert len(lines) == 50
        # Check some expected messages exist
        content = ''.join(lines)
        assert "Thread 0" in content
        assert "Thread 4" in content

    def test_log_preserves_order(self, temp_output_file):
        """_log() maintains order despite thread safety."""
        for i in range(20):
            _log(temp_output_file, f"Message {i}")

        with open(temp_output_file, 'r') as f:
            lines = [line.strip() for line in f.readlines()]

        for i in range(20):
            assert f"Message {i}" in lines[i]


# ═════════════════════════════════════════════════════════════════════════════
# TEST: run_cmd() - Successful execution
# ═════════════════════════════════════════════════════════════════════════════

class TestRunCmdSuccess:
    """Test run_cmd() function for successful command execution."""

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_success(self, mock_print, mock_run, temp_output_file):
        """run_cmd() executes command successfully."""
        mock_result = MagicMock()
        mock_result.stdout = "output"
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig()
        stdout, stderr, code = run_cmd(
            ["echo", "test"],
            "Test command",
            temp_output_file,
            config
        )

        assert stdout == "output"
        assert stderr == ""
        assert code == 0

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_with_stderr_verbose_off(self, mock_print, mock_run, temp_output_file):
        """run_cmd() doesn't log stderr in non-verbose mode."""
        mock_result = MagicMock()
        mock_result.stdout = "output"
        mock_result.stderr = "warning"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig(verbose=False)
        stdout, stderr, code = run_cmd(
            ["test"],
            "Command",
            temp_output_file,
            config
        )

        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "warning" not in content

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_with_stderr_verbose_on(self, mock_print, mock_run, temp_output_file):
        """run_cmd() logs stderr in verbose mode."""
        mock_result = MagicMock()
        mock_result.stdout = "output"
        mock_result.stderr = "warning message"
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig(verbose=True)
        stdout, stderr, code = run_cmd(
            ["test"],
            "Command",
            temp_output_file,
            config
        )

        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "warning message" in content

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_logs_stdout(self, mock_print, mock_run, temp_output_file):
        """run_cmd() logs command output."""
        mock_result = MagicMock()
        mock_result.stdout = "command output"
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig()
        run_cmd(["cmd"], "Test", temp_output_file, config)

        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "command output" in content

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_logs_command_description(self, mock_print, mock_run, temp_output_file):
        """run_cmd() logs command description."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig()
        run_cmd(["test"], "My command description", temp_output_file, config)

        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "My command description" in content

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_logs_command_args(self, mock_print, mock_run, temp_output_file):
        """run_cmd() logs full command arguments."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig()
        run_cmd(["nmap", "-sV", "example.com"], "Nmap scan", temp_output_file, config)

        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "nmap" in content
        assert "-sV" in content
        assert "example.com" in content


# ═════════════════════════════════════════════════════════════════════════════
# TEST: run_cmd() - Failure cases
# ═════════════════════════════════════════════════════════════════════════════

class TestRunCmdFailure:
    """Test run_cmd() function for command failures."""

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_non_zero_exit(self, mock_print, mock_run, temp_output_file):
        """run_cmd() handles non-zero exit codes."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = "error message"
        mock_result.returncode = 1
        mock_run.return_value = mock_result

        config = MockConfig()
        stdout, stderr, code = run_cmd(
            ["false"],
            "Failing command",
            temp_output_file,
            config
        )

        assert code == 1

    @patch('subprocess.run', side_effect=subprocess.TimeoutExpired("cmd", 30))
    @patch('builtins.print')
    def test_run_cmd_timeout(self, mock_print, mock_run, temp_output_file):
        """run_cmd() handles command timeout."""
        config = MockConfig()
        stdout, stderr, code = run_cmd(
            ["long_command"],
            "Timeout command",
            temp_output_file,
            config,
            timeout=30
        )

        assert code == -1
        assert stdout == ""
        assert stderr == ""

        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "TIMEOUT" in content

    @patch('subprocess.run', side_effect=FileNotFoundError("cmd not found"))
    @patch('builtins.print')
    def test_run_cmd_tool_not_found(self, mock_print, mock_run, temp_output_file):
        """run_cmd() raises ToolNotFound when command not in PATH."""
        config = MockConfig()

        with pytest.raises(ToolNotFound):
            run_cmd(
                ["nonexistent_tool"],
                "Missing tool",
                temp_output_file,
                config
            )

    @patch('subprocess.run', side_effect=PermissionError("Permission denied"))
    @patch('builtins.print')
    def test_run_cmd_permission_error(self, mock_print, mock_run, temp_output_file):
        """run_cmd() handles permission errors."""
        config = MockConfig()
        stdout, stderr, code = run_cmd(
            ["restricted"],
            "Permission denied command",
            temp_output_file,
            config
        )

        assert code == -1
        assert stdout == ""
        assert stderr == ""

        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "Permission denied" in content

    @patch('subprocess.run', side_effect=Exception("Generic error"))
    @patch('builtins.print')
    def test_run_cmd_generic_exception(self, mock_print, mock_run, temp_output_file):
        """run_cmd() handles generic exceptions."""
        config = MockConfig()
        stdout, stderr, code = run_cmd(
            ["cmd"],
            "Error command",
            temp_output_file,
            config
        )

        assert code == -1
        assert stdout == ""
        assert stderr == ""


# ═════════════════════════════════════════════════════════════════════════════
# TEST: run_cmd() - Edge cases
# ═════════════════════════════════════════════════════════════════════════════

class TestRunCmdEdgeCases:
    """Test run_cmd() function for edge cases."""

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_empty_stdout(self, mock_print, mock_run, temp_output_file):
        """run_cmd() handles empty stdout."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig()
        stdout, stderr, code = run_cmd(
            ["true"],
            "No output",
            temp_output_file,
            config
        )

        assert stdout == ""
        assert code == 0

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_large_output(self, mock_print, mock_run, temp_output_file):
        """run_cmd() handles large command output."""
        large_output = "x" * 10000
        mock_result = MagicMock()
        mock_result.stdout = large_output
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig()
        stdout, stderr, code = run_cmd(
            ["big_output"],
            "Large output",
            temp_output_file,
            config
        )

        assert stdout == large_output
        assert code == 0

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_with_newlines_in_output(self, mock_print, mock_run, temp_output_file):
        """run_cmd() preserves newlines in output."""
        output = "line1\nline2\nline3"
        mock_result = MagicMock()
        mock_result.stdout = output
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig()
        stdout, stderr, code = run_cmd(
            ["multiline"],
            "Multiline output",
            temp_output_file,
            config
        )

        assert stdout == output
        with open(temp_output_file, 'r') as f:
            content = f.read()
        assert "line1" in content
        assert "line2" in content
        assert "line3" in content

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_preserves_command_list(self, mock_print, mock_run, temp_output_file):
        """run_cmd() doesn't modify command list argument."""
        cmd = ["nmap", "-sV", "target.com"]
        original_cmd = cmd.copy()
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig()
        run_cmd(cmd, "Test", temp_output_file, config)

        assert cmd == original_cmd

    @patch('subprocess.run')
    @patch('builtins.print')
    def test_run_cmd_timeout_parameter(self, mock_print, mock_run, temp_output_file):
        """run_cmd() respects custom timeout parameter."""
        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 0
        mock_run.return_value = mock_result

        config = MockConfig()
        run_cmd(["cmd"], "Test", temp_output_file, config, timeout=60)

        mock_run.assert_called_once()
        assert mock_run.call_args[1]['timeout'] == 60


# ═════════════════════════════════════════════════════════════════════════════
# TEST: ToolNotFound exception
# ═════════════════════════════════════════════════════════════════════════════

class TestToolNotFound:
    """Test ToolNotFound exception."""

    def test_tool_not_found_is_exception(self):
        """ToolNotFound is an Exception."""
        assert issubclass(ToolNotFound, Exception)

    def test_tool_not_found_message(self):
        """ToolNotFound includes error message."""
        exc = ToolNotFound("Tool 'nmap' not found")
        assert "nmap" in str(exc)

    def test_tool_not_found_from_exception(self):
        """ToolNotFound can be raised from another exception."""
        original = FileNotFoundError("No such file")
        try:
            raise original
        except FileNotFoundError as e:
            exc = ToolNotFound("Tool not found")
            assert isinstance(exc, Exception)
