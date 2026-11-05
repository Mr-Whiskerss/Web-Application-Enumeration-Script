"""
Scan State Management

Handles:
- Scan state tracking (resumability, phase completion)
- Discovered state (URLs, parameters, endpoints)
- Scope checking (CIDR/domain validation)
"""

import os
import json
import socket
import logging
import ipaddress
import threading
from datetime import datetime
from typing import List, Set, Optional
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("webrecon")


class DiscoveredState:
    """Shared state for discovered URLs, parameters, and endpoints."""

    def __init__(self):
        self._lock = threading.Lock()
        self.urls: Set[str] = set()
        self.params: Set[str] = set()
        self.endpoints: Set[str] = set()  # path-only, no query

    def add_urls(self, urls):
        """Add URLs and extract endpoints/parameters."""
        with self._lock:
            for u in urls:
                if not u:
                    continue
                self.urls.add(u)
                try:
                    parsed = urlparse(u)
                    if parsed.path:
                        self.endpoints.add(parsed.path)
                    if parsed.query:
                        for k in parse_qs(parsed.query).keys():
                            self.params.add(k)
                except Exception:
                    pass

    def add_params(self, params):
        """Add parameters."""
        with self._lock:
            self.params.update(p for p in params if p)

    def get_urls_with_params(self, limit: int = 50) -> List[str]:
        """Get URLs that have query parameters."""
        with self._lock:
            return [u for u in self.urls if "?" in u and "=" in u][:limit]


class ScanState:
    """Track scan progress for resumability."""

    def __init__(self, state_file: str, target: str):
        self._file = state_file
        self._target = target
        self._done: List[str] = []
        self._start = datetime.now().isoformat()

        if os.path.exists(state_file):
            try:
                with open(state_file, "r") as fh:
                    d = json.load(fh)
                    saved_target = d.get("target")

                    if saved_target and saved_target != target:
                        print(
                            f"  \033[93m[STATE] Previous state was for '{saved_target}' — "
                            f"clearing (current target: '{target}')\033[0m"
                        )
                        try:
                            os.remove(state_file)
                        except OSError as e:
                            if logger:
                                logger.warning(f"Failed to remove old state file: {e}")
                        return

                    self._done = d.get("done", [])
                    self._start = d.get("start", self._start)

                    if self._done:
                        print(f"  \033[93m[RESUME] Completed phases: {', '.join(self._done)}\033[0m")
                        if logger:
                            logger.info(f"Resuming scan with completed phases: {self._done}")

            except json.JSONDecodeError as e:
                if logger:
                    logger.warning(f"Corrupted state file (invalid JSON): {e}. Starting fresh.")
                print(f"  \033[93m[STATE] State file corrupted, starting fresh.\033[0m")
            except IOError as e:
                if logger:
                    logger.warning(f"Failed to read state file: {e}")
                print(f"  \033[93m[STATE] Could not read state file, starting fresh.\033[0m")
            except Exception as e:
                if logger:
                    logger.error(f"Unexpected error loading state: {e}")
                print(f"  \033[93m[STATE] Unexpected error loading state, starting fresh.\033[0m")

    def done(self, phase: str) -> bool:
        """Check if phase is marked complete."""
        return phase in self._done

    def mark(self, phase: str):
        """Mark a phase as complete. Uses atomic write to prevent corruption."""
        if phase not in self._done:
            self._done.append(phase)

            try:
                temp_file = self._file + ".tmp"
                with open(temp_file, "w") as fh:
                    json.dump(
                        {
                            "target": self._target,
                            "done": self._done,
                            "start": self._start,
                            "updated": datetime.now().isoformat(),
                        },
                        fh,
                        indent=2,
                    )

                if os.name == "nt":  # Windows
                    if os.path.exists(self._file):
                        os.replace(temp_file, self._file)
                    else:
                        os.rename(temp_file, self._file)
                else:  # POSIX
                    os.replace(temp_file, self._file)

                if logger:
                    logger.debug(f"Marked phase as complete: {phase}")

            except IOError as e:
                if logger:
                    logger.error(f"Failed to write state file: {e}")
            except Exception as e:
                if logger:
                    logger.error(f"Unexpected error marking phase: {e}")

    def clear(self):
        """Clear state file."""
        self._done = []
        if os.path.exists(self._file):
            os.remove(self._file)


class ScopeChecker:
    """Validate targets against scope (IPv4/IPv6 CIDRs and domains)."""

    def __init__(self, scope_file: Optional[str] = None):
        self.domains: List[str] = []
        self.cidrs: List = []  # IPv4Network | IPv6Network
        self.enabled = scope_file is not None

        if scope_file and os.path.exists(scope_file):
            for line in open(scope_file):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Try IPv4 then IPv6 network, fall back to domain
                try:
                    self.cidrs.append(ipaddress.IPv4Network(line, strict=False))
                    continue
                except ValueError:
                    pass

                try:
                    self.cidrs.append(ipaddress.IPv6Network(line, strict=False))
                    continue
                except ValueError:
                    pass

                self.domains.append(line.lower().lstrip("*."))

    def check(self, target: str) -> bool:
        """Check if target is in scope."""
        if not self.enabled:
            return True

        # IP literal check
        try:
            addr = ipaddress.ip_address(target)
            return any(addr in net for net in self.cidrs)
        except ValueError:
            pass

        # Domain match
        t = target.lower()
        if any(t == d or t.endswith("." + d) for d in self.domains):
            return True

        # Resolve domain → check IP against CIDRs
        if self.cidrs:
            try:
                resolved = socket.gethostbyname(target)
                addr = ipaddress.ip_address(resolved)
                for net in self.cidrs:
                    try:
                        if addr in net:
                            return True
                    except (TypeError, ValueError):
                        continue
            except Exception:
                pass

        return False
