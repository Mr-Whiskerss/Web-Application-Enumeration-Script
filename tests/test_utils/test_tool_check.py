"""
Comprehensive unit tests for web_app.utils.tool_check module.

Tests cover:
  - _tool_ok(): Check if tools are available in PATH
  - _is_root(): Check root privileges
  - _sudo(): Determine if sudo is needed
  - Thread-safe tool tracking
"""

import pytest
import os
import threading
import tempfile
from unittest.mock import patch, MagicMock, mock_open

from web_app.utils.tool_check import _tool_ok, _is_root, _sudo


# ═════════════════════════════════════════════════════════════════════════════
# TEST: _is_root()
# ═════════════════════════════════════════════════════════════════════════════

class TestIsRoot:
    """Test _is_root() function for privilege checking."""

    @patch('os.geteuid', return_value=0)
    def test_is_root_when_uid_zero(self, mock_geteuid):
        """_is_root() returns True when UID is 0."""
        assert _is_root() is True
        mock_geteuid.assert_called_once()

    @patch('os.geteuid', return_value=1000)
    def test_is_root_when_uid_nonzero(self, mock_geteuid):
        """_is_root() returns False when UID is non-zero."""
        assert _is_root() is False
        mock_geteuid.assert_called_once()

    @patch('os.geteuid', return_value=1)
    def test_is_root_uid_one(self, mock_geteuid):
        """_is_root() returns False for UID 1."""
        assert _is_root() is False

    @patch('os.geteuid', return_value=65534)
    def test_is_root_uid_nobody(self, mock_geteuid):
        """_is_root() returns False for UID of nobody user."""
        assert _is_root() is False

    @patch('os.geteuid')
    def test_is_root_called_once(self, mock_geteuid):
        """_is_root() calls os.geteuid() exactly once."""
        mock_geteuid.return_value = 0
        _is_root()
        _is_root()
        assert mock_geteuid.call_count == 2


# ═════════════════════════════════════════════════════════════════════════════
# TEST: _sudo()
# ═════════════════════════════════════════════════════════════════════════════

class TestSudo:
    """Test _sudo() function for sudo determination."""

    @patch('web_app.utils.tool_check._is_root', return_value=True)
    def test_sudo_when_root(self, mock_is_root):
        """_sudo() returns empty list when running as root."""
        result = _sudo()
        assert result == []
        mock_is_root.assert_called_once()

    @patch('web_app.utils.tool_check._is_root', return_value=False)
    def test_sudo_when_not_root(self, mock_is_root):
        """_sudo() returns ['sudo'] when not running as root."""
        result = _sudo()
        assert result == ["sudo"]
        mock_is_root.assert_called_once()

    @patch('web_app.utils.tool_check._is_root', return_value=True)
    def test_sudo_returns_list_type(self, mock_is_root):
        """_sudo() always returns a list."""
        result = _sudo()
        assert isinstance(result, list)

    @patch('web_app.utils.tool_check._is_root', return_value=False)
    def test_sudo_result_is_mutable(self, mock_is_root):
        """_sudo() result is a mutable list."""
        result = _sudo()
        result.append("extra")
        assert result == ["sudo", "extra"]

    @patch('web_app.utils.tool_check._is_root', return_value=True)
    def test_sudo_empty_list_is_independent(self, mock_is_root):
        """_sudo() returns independent list instances when root."""
        result1 = _sudo()
        result2 = _sudo()
        assert result1 is not result2


# ═════════════════════════════════════════════════════════════════════════════
# TEST: _tool_ok()
# ═════════════════════════════════════════════════════════════════════════════

class TestToolOk:
    """Test _tool_ok() function for tool availability checking."""

    @patch('shutil.which', return_value='/usr/bin/nmap')
    def test_tool_ok_tool_found(self, mock_which):
        """_tool_ok() returns True when tool is found."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            result = _tool_ok("nmap", temp_file)
            assert result is True
            mock_which.assert_called_once_with("nmap")
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', return_value=None)
    @patch('builtins.print')
    def test_tool_ok_tool_not_found(self, mock_print, mock_which):
        """_tool_ok() returns False when tool is not found."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            result = _tool_ok("missing_tool", temp_file)
            assert result is False
            mock_which.assert_called_once_with("missing_tool")
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', return_value=None)
    @patch('builtins.print')
    def test_tool_ok_logs_to_file(self, mock_print, mock_which):
        """_tool_ok() logs missing tool to output file."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            _tool_ok("missing", temp_file)
            with open(temp_file, 'r') as f:
                content = f.read()
            assert "missing" in content
            assert "not installed" in content
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', return_value=None)
    @patch('builtins.print')
    def test_tool_ok_prints_warning(self, mock_print, mock_which):
        """_tool_ok() prints warning when tool not found."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            _tool_ok("missing", temp_file)
            mock_print.assert_called()
            printed_text = str(mock_print.call_args)
            assert "missing" in printed_text or "not installed" in printed_text
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', return_value='/usr/bin/tool1')
    def test_tool_ok_multiple_tools_found(self, mock_which):
        """_tool_ok() works with multiple tool checks."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            result1 = _tool_ok("tool1", temp_file)
            mock_which.return_value = '/usr/bin/tool2'
            result2 = _tool_ok("tool2", temp_file)
            assert result1 is True
            assert result2 is True
            assert mock_which.call_count == 2
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', return_value=None)
    @patch('builtins.print')
    def test_tool_ok_tracks_missing_tools_thread_safe(self, mock_print, mock_which):
        """_tool_ok() thread-safely tracks missing tools."""
        from web_app.utils import tool_check
        # Reset missing tools tracking
        tool_check._MISSING_TOOLS.clear()

        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            results = []
            def check_tool(name):
                result = _tool_ok(name, temp_file)
                results.append(result)

            threads = []
            for i in range(5):
                t = threading.Thread(target=check_tool, args=(f"tool{i}",))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            # All should be False (tools not found)
            assert all(r is False for r in results)
            # All tool names should be tracked
            assert len(tool_check._MISSING_TOOLS) == 5
        finally:
            tool_check._MISSING_TOOLS.clear()
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', return_value='/usr/bin/nmap')
    def test_tool_ok_with_full_path(self, mock_which):
        """_tool_ok() works with tool names containing paths."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            result = _tool_ok("nmap", temp_file)
            assert result is True
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', return_value='/usr/bin/tool')
    def test_tool_ok_returns_boolean(self, mock_which):
        """_tool_ok() always returns a boolean."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            result = _tool_ok("tool", temp_file)
            assert isinstance(result, bool)
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', return_value=None)
    @patch('builtins.print')
    def test_tool_ok_handles_exception_gracefully(self, mock_print, mock_which):
        """_tool_ok() handles exceptions gracefully."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            # This should not raise an exception
            result = _tool_ok("tool", temp_file)
            assert result is False
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', return_value=None)
    @patch('builtins.print', side_effect=Exception("Print error"))
    def test_tool_ok_resilient_to_print_error(self, mock_print, mock_which):
        """_tool_ok() continues even if printing fails."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            # Should still log to file despite print error
            result = _tool_ok("tool", temp_file)
            assert result is False
            assert os.path.exists(temp_file)
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


# ═════════════════════════════════════════════════════════════════════════════
# TEST: Integration tests
# ═════════════════════════════════════════════════════════════════════════════

class TestToolCheckIntegration:
    """Integration tests for tool_check functions."""

    @patch('web_app.utils.tool_check._is_root', return_value=True)
    def test_root_sudo_integration(self, mock_is_root):
        """When root, _sudo() returns empty and _is_root() is True."""
        assert _is_root() is True
        assert _sudo() == []

    @patch('web_app.utils.tool_check._is_root', return_value=False)
    def test_non_root_sudo_integration(self, mock_is_root):
        """When not root, _sudo() returns ['sudo']."""
        assert _is_root() is False
        assert _sudo() == ["sudo"]

    @patch('shutil.which', return_value='/usr/bin/sudo')
    def test_tool_check_sudo_command(self, mock_which):
        """_tool_ok() can verify sudo command itself."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            result = _tool_ok("sudo", temp_file)
            assert result is True
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)

    @patch('shutil.which', side_effect=lambda x: '/usr/bin/' + x if x in ['nmap', 'python3'] else None)
    @patch('builtins.print')
    def test_multiple_tool_checks(self, mock_print, mock_which):
        """_tool_ok() works with multiple sequential tool checks."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_file = f.name
        try:
            assert _tool_ok("nmap", temp_file) is True
            assert _tool_ok("python3", temp_file) is True
            assert _tool_ok("missing", temp_file) is False
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
