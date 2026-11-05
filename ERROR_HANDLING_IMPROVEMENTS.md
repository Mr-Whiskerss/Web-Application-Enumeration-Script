# Error Handling Improvements - WebRecon v3.3.0

## Overview
Comprehensive error handling improvements have been made throughout the script to provide better debugging, recovery, and user feedback. The changes transform silent failures into logged events with context-aware error messages.

## Key Improvements

### 1. **Custom Exception Hierarchy**
Added custom exception classes for specific error types:
- `WebReconException` - Base exception for all WebRecon errors
- `ToolNotFound` - Tool is not installed or not in PATH
- `NetworkError` - Network-related errors (connection, timeout, DNS)
- `ParseError` - Error parsing response or data
- `ConfigError` - Configuration errors

**Benefits:**
- Allows specific exception handling based on error type
- Makes error context clear to users
- Enables different recovery strategies per error

### 2. **Structured Logging System**
Added full logging support with `setup_logging()` function:
- **Log Levels:** DEBUG (verbose mode), INFO, WARNING, ERROR
- **Output:** Console logging with timestamps
- **Verbosity Control:** `-v` flag enables DEBUG-level logging
- **Auto-initialization:** Logger is set up during `main()` startup

**Benefits:**
- All errors are now logged with timestamps
- Verbose mode (`-v`) provides detailed debugging info
- No more silent failures - every error is recorded
- Users can grep logs for specific issues

### 3. **Improved run_cmd() Function**
Enhanced subprocess execution with detailed error handling:

```python
# Now catches specific exceptions:
- subprocess.TimeoutExpired → logs timeout, returns error code -1
- FileNotFoundError → raises ToolNotFound exception
- PermissionError → logs permission issue
- Other exceptions → detailed error context + logging
```

**Changes:**
- Each error type has a specific handling path
- Tool errors raise ToolNotFound (can be caught by phases)
- Non-zero exit codes are logged as warnings
- stderr output is logged in verbose mode

### 4. **HTTP Session Error Handling (RateLimitedSession)**
Enhanced rate-limit awareness and error recovery:

```python
# Catches specific request errors:
- ConnectTimeout → NetworkError
- ReadTimeout → NetworkError
- ConnectionError → NetworkError
- RequestException → NetworkError
- Retry-After header parsing errors → logged + ignored
```

**Changes:**
- All request exceptions are wrapped as NetworkError
- Rate limit backoff logic includes error logging
- Broken Retry-After headers don't crash backoff logic
- Exponential backoff caps at 60s to prevent indefinite waits

### 5. **JWT Analysis Error Handling**
Improved JWT parsing with per-part error handling:

```python
# Now catches:
- Malformed JWT (wrong number of parts)
- Base64 decode failures (header)
- Base64 decode failures (payload)
- JSON parse failures per-part
```

**Benefits:**
- Single malformed JWT no longer breaks the entire phase
- Each failure is logged with context
- Parser continues to next JWT
- Users see debug logs for why JWTs were skipped

### 6. **ScanState Error Handling**
Robust state file management with atomic writes:

```python
# Improvements:
- JSON decode errors → log + start fresh (no corruption)
- File read errors → log + graceful fallback
- Atomic writes using temp file + rename
- Cross-platform compatibility (Windows + POSIX)
```

**Benefits:**
- Corrupted state files don't crash scan
- Partial writes can't corrupt state
- Clear logging of why state was reset
- Users can safely interrupt and resume scans

### 7. **Authentication/Session Error Handling**
Enhanced `revalidate_session()` with specific error types:

```python
# Catches and handles:
- Timeout → warning log
- Request exceptions → error log
- Missing auth text → warning + description
- Unexpected errors → exception log
```

**Benefits:**
- Session check failures are clearly reported
- Different errors have appropriate severity
- Debug info helps troubleshoot auth issues

### 8. **Webhook & PentestDB Error Handling**
Improved integration error handling:

```python
# Catches:
- Timeout → warning log
- HTTP errors (4xx/5xx) → warning log
- Request exceptions → error log
- Unexpected errors → exception log
```

**Benefits:**
- Integration failures don't crash scans
- Failed notifications are logged
- Users know if webhooks failed
- HTTP errors are visible in logs

### 9. **Scheme Detection Error Handling**
Better handling of scheme detection failures:

```python
# Now catches:
- ConnectionError → debug log (silently try next scheme)
- Timeout → debug log
- Other errors → debug log with detail
- Falls back to "http" if both fail (warning log)
```

**Benefits:**
- Clear logging of why scheme detection failed
- Explicit fallback to http
- Users understand target connectivity issues

### 10. **Main Loop Error Handling**
Comprehensive top-level error catching:

```python
# Now catches and handles:
- KeyboardInterrupt → graceful shutdown
- ConfigError → clear error message
- NetworkError → target connectivity issue
- Generic exceptions → detailed error + logging
```

**Benefits:**
- Each error type has appropriate messaging
- Traceback only shown in verbose mode
- Errors are logged to both console and report
- Users get helpful context for each error type

## Usage

### Normal Mode (Quiet)
```bash
python3 web_app.py -t example.com
# Only shows errors/warnings
```

### Verbose Mode (Debugging)
```bash
python3 web_app.py -t example.com -v
# Shows all DEBUG logs, full tracebacks on errors
```

### Check Logs
```bash
# View all errors logged during scan
grep "ERROR" ~/.webrecon.log

# View all warnings
grep "WARNING" ~/.webrecon.log

# Debug specific phase
grep "jwt_analysis" ~/.webrecon.log
```

## Error Recovery Strategies

### Tool Not Found
- Phase is skipped
- Continues with other phases
- Missing tools listed in summary

### Network Timeout
- Request is retried after backoff
- Excessive timeouts trigger rate-limit backoff
- Session can be revalidated

### Corrupted State File
- Scanner starts fresh (doesn't crash)
- Old state is abandoned
- Clear warning to user

### Rate Limit (429/503)
- Automatic exponential backoff
- Respects Retry-After header
- Max backoff 120s to prevent hangs

### JWT Parse Failure
- Single JWT is skipped
- Scanner continues with next JWT
- Failure is logged for debugging

## Backwards Compatibility

✓ All changes are backwards compatible:
- Existing command-line arguments unchanged
- Output formats (Markdown/JSON/HTML) unchanged
- Report structure unchanged
- No breaking changes to phases

## Testing Recommendations

1. **Test with broken connectivity:**
   ```bash
   python3 web_app.py -t nonexistent.invalid -v
   # Should show connection errors gracefully
   ```

2. **Test with missing tools:**
   ```bash
   # Remove a tool from PATH and run
   PATH=/tmp:$PATH python3 web_app.py -t example.com
   # Should skip phases, list in summary
   ```

3. **Test verbose logging:**
   ```bash
   python3 web_app.py -t example.com -v 2>&1 | grep "DEBUG"
   # Should show detailed debug output
   ```

4. **Test state recovery:**
   ```bash
   python3 web_app.py -t example.com &
   # Ctrl+C after a few phases
   python3 web_app.py -t example.com --resume
   # Should resume from last completed phase
   ```

## Future Enhancements

- Add log file output (`--log-file` option)
- Add structured JSON logging option
- Add metrics collection (success/error rates per phase)
- Add error recovery strategies per phase type
- Add email notification for critical errors
