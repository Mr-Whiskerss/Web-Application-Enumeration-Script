"""
HTTP Session Management

Handles HTTP requests with rate limiting, authentication, and error handling.
"""

import time
import logging
import requests
import threading
from email.utils import parsedate_to_datetime
from typing import Optional

logger = logging.getLogger("webrecon")

# Will get Fore and NetworkError from parent on import
Fore = None
NetworkError = None


class RateLimitedSession(requests.Session):
    """HTTP session with adaptive rate limiting and backoff.

    Shared class-level backoff ensures the whole scan throttles together.
    """

    _lock = threading.Lock()
    _consecutive_429 = 0
    _backoff_until = 0.0
    _announced_backoff = False

    def request(self, method, url, **kwargs):
        """Make HTTP request with rate-limit handling and backoff."""
        # Respect any active backoff window
        with RateLimitedSession._lock:
            wait = RateLimitedSession._backoff_until - time.time()
        if wait > 0:
            time.sleep(min(wait, 120))

        try:
            resp = super().request(method, url, **kwargs)
        except requests.exceptions.ConnectTimeout:
            if logger:
                logger.debug(f"Connection timeout on {method} {url}")
            raise NetworkError(f"Connection timeout: {url}") from None
        except requests.exceptions.ReadTimeout:
            if logger:
                logger.debug(f"Read timeout on {method} {url}")
            raise NetworkError(f"Read timeout: {url}") from None
        except requests.exceptions.ConnectionError as e:
            if logger:
                logger.debug(f"Connection error on {method} {url}: {e}")
            raise NetworkError(f"Connection error: {url}") from e
        except requests.exceptions.RequestException as e:
            if logger:
                logger.debug(f"Request exception on {method} {url}: {e}")
            raise NetworkError(f"Request failed: {url}") from e

        # Handle rate limiting
        if resp.status_code in (429, 503):
            retry_after = None
            ra_raw = resp.headers.get("Retry-After")

            if ra_raw:
                ra_raw = ra_raw.strip()
                if ra_raw.isdigit():
                    retry_after = int(ra_raw)
                else:
                    try:
                        dt = parsedate_to_datetime(ra_raw)
                        retry_after = max(0, (dt.timestamp() - time.time()))
                    except Exception as e:
                        if logger:
                            logger.debug(f"Failed to parse Retry-After header: {e}")
                        retry_after = None

            with RateLimitedSession._lock:
                RateLimitedSession._consecutive_429 += 1
                expo = min(2 ** RateLimitedSession._consecutive_429, 60)
                backoff = (
                    min(retry_after, 120)
                    if retry_after is not None
                    else expo
                )
                RateLimitedSession._backoff_until = time.time() + backoff

                if not RateLimitedSession._announced_backoff:
                    src = "Retry-After" if retry_after is not None else "exponential"
                    try:
                        print(
                            f"  {Fore.YELLOW}⏱ Rate limited (HTTP {resp.status_code}) "
                            f"— backing off {backoff:.0f}s ({src})"
                        )
                    except:
                        print(f"  Rate limited (HTTP {resp.status_code}) — backing off {backoff:.0f}s ({src})")
                    RateLimitedSession._announced_backoff = True
                    if logger:
                        logger.warning(
                            f"Rate limited: {resp.status_code}, backing off {backoff:.0f}s"
                        )

        elif resp.status_code < 400:
            with RateLimitedSession._lock:
                if RateLimitedSession._consecutive_429 > 0:
                    RateLimitedSession._consecutive_429 = 0
                    RateLimitedSession._announced_backoff = False

        return resp


def make_session(config) -> requests.Session:
    """Create HTTP session with auth, proxy, and rate limiting."""
    s = RateLimitedSession()
    s.headers["User-Agent"] = config.user_agent
    s.verify = False

    if config.proxy:
        s.proxies = {"http": config.proxy, "https": config.proxy}

    # Authenticated session: cookies
    if config.cookie:
        for kv in config.cookie.split(";"):
            kv = kv.strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                s.cookies.set(k.strip(), v.strip())

    # Extra headers (Authorization: Bearer …, X-API-Key: …, etc.)
    if config.extra_headers:
        for h in config.extra_headers:
            if ":" in h:
                k, v = h.split(":", 1)
                s.headers[k.strip()] = v.strip()

    return s


def detect_scheme(target: str, config) -> str:
    """Detect if target responds to https or http. Defaults to http if both fail."""
    sess = make_session(config)
    for scheme in ("https", "http"):
        try:
            resp = sess.get(
                f"{scheme}://{target}",
                timeout=config.timeout,
                allow_redirects=False,
            )
            try:
                print(f"  \033[92m✓ Scheme detected: {scheme}\033[0m")  # Green
            except:
                print(f"  * Scheme detected: {scheme}")
            if logger:
                logger.info(f"Detected scheme for {target}: {scheme}")
            return scheme
        except requests.exceptions.ConnectionError as e:
            if logger:
                logger.debug(f"{scheme} connection failed for {target}: {e}")
            continue
        except requests.exceptions.Timeout as e:
            if logger:
                logger.debug(f"{scheme} timeout for {target}: {e}")
            continue
        except Exception as e:
            if logger:
                logger.debug(f"Error detecting {scheme} for {target}: {e}")
            continue

    if logger:
        logger.warning(f"Could not detect scheme for {target}, defaulting to http")
    return "http"


def revalidate_session(cfg, out: str) -> bool:
    """Verify session is still authenticated if auth-check-url/text configured."""
    if not cfg.auth_check_url or not cfg.auth_check_text:
        return True

    try:
        sess = make_session(cfg)
        r = sess.get(cfg.auth_check_url, timeout=cfg.timeout)

        if cfg.auth_check_text in r.text:
            if logger:
                logger.info(f"Session authentication verified at {cfg.auth_check_url}")
            return True

        msg = "Auth check failed — session may have expired!"
        try:
            print(f"  \033[91m⚠ {msg}\033[0m")  # Red
        except:
            print(f"  ⚠ {msg}")
        if logger:
            logger.warning(
                f"Auth check failed: expected text not found in {cfg.auth_check_url}"
            )
        return False

    except requests.exceptions.Timeout as e:
        msg = f"Auth check timeout at {cfg.auth_check_url}"
        try:
            print(f"  \033[93m⚠ {msg}\033[0m")  # Yellow
        except:
            print(f"  ⚠ {msg}")
        if logger:
            logger.warning(f"Auth check timeout: {e}")
        return False

    except requests.exceptions.RequestException as e:
        msg = f"Auth check network error: {e}"
        try:
            print(f"  \033[93m⚠ {msg}\033[0m")  # Yellow
        except:
            print(f"  ⚠ {msg}")
        if logger:
            logger.error(f"Auth check failed with network error: {e}")
        return False

    except Exception as e:
        msg = f"Auth check error: {type(e).__name__}: {str(e)[:80]}"
        try:
            print(f"  \033[93m⚠ {msg}\033[0m")  # Yellow
        except:
            print(f"  ⚠ {msg}")
        if logger:
            logger.exception("Unexpected error in auth check")
        return False
