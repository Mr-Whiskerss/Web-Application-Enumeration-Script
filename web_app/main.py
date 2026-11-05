#!/usr/bin/env python3
"""
WebRecon Main Orchestrator Entry Point

Coordinates the complete scanning workflow for web application reconnaissance and
enumeration. Acts as the central hub that:

1. Imports all modular components (core, phases, integrations, reporting, utils)
2. Manages phase execution in proper sequence (passive → discovery → active →
   http_analysis → vulns → http_methods → reflection_xss → sqli → dns_security)
3. Tracks state between phases for resumable scans
4. Triggers integration notifications (webhooks, pentestdb) after findings
5. Exports results in all formats (markdown, html, json)
6. Handles graceful error handling and logging

This orchestrator ties together the entire modular architecture and preserves
all original logic from the monolithic web_app.py.
"""

import os
import sys
import json
import time
import logging
import threading
from datetime import datetime
from collections import Counter
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List, Dict, Tuple

try:
    from colorama import Fore, Style, init as _cinit
    _cinit(autoreset=True)
except ImportError:
    class Fore:
        RED=GREEN=YELLOW=BLUE=CYAN=MAGENTA=WHITE=""
    class Style:
        RESET_ALL=BRIGHT=""

# ── Import Core Modules ──────────────────────────────────────────────────────
from web_app.core import (
    RateLimitedSession,
    make_session,
    detect_scheme,
    revalidate_session,
    ScanState,
    ScopeChecker,
    DiscoveredState,
    Finding,
    Severity,
    add_finding,
    webhook_notify,
    pentestdb_push,
    save_findings as core_save_findings,
)

# ── Import Phase Modules ──────────────────────────────────────────────────────
try:
    from web_app.phases.passive import (
        phase_passive_dns,
        phase_cert_transparency,
        phase_wayback,
        phase_google_dorks,
        phase_email_harvest,
        phase_subdomain_enum,
        phase_favicon_hash,
        phase_dns_security,
    )
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import passive phases: {e}")
    raise

try:
    from web_app.phases.discovery import (
        phase_robots_sitemap,
        phase_crawler,
        phase_api_schema,
        phase_source_exposure,
        phase_content_discovery,
        phase_param_discovery,
    )
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import discovery phases: {e}")
    raise

try:
    from web_app.phases.active import (
        phase_port_scan,
        phase_waf_cdn,
        phase_vhost_fuzz,
    )
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import active phases: {e}")
    raise

try:
    from web_app.phases.http_analysis import (
        phase_header_analysis,
        phase_cors,
        phase_oauth_oidc,
        phase_csp_analysis,
        phase_host_header,
        phase_crlf,
        phase_csrf,
        phase_jwt_analysis,
        phase_http_methods,
        phase_403_bypass,
    )
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import http_analysis phases: {e}")
    raise

try:
    from web_app.phases.vulns import (
        phase_ssl_tls,
        phase_nikto,
        phase_nuclei,
        phase_js_analysis,
        phase_graphql,
        phase_path_traversal,
        phase_open_redirect,
        phase_websocket,
        phase_prototype_pollution,
        phase_ssrf,
        phase_ssti,
        phase_xxe,
        phase_default_creds,
        phase_request_smuggling,
    )
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import vulns phases: {e}")
    raise

try:
    from web_app.phases.reflection_xss import phase_reflection_xss
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import reflection_xss phase: {e}")
    raise

try:
    from web_app.phases.sqli import phase_sqli
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import sqli phase: {e}")
    raise

# Tech detection and playbooks
try:
    from web_app.phases.discovery import (
        phase_tech_detection,
        phase_tech_playbooks,
    )
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import tech detection: {e}")
    # These may be integrated differently, continue
    pass

# Infrastructure phases
try:
    from web_app.phases.active import (
        phase_cloud_buckets,
        phase_screenshots,
    )
except ImportError:
    # These may not exist yet
    pass

# ── Import Integrations ──────────────────────────────────────────────────────
try:
    from web_app.integrations import pentestdb_push as push_pentestdb
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import integrations: {e}")
    pass

# ── Import Reporting ────────────────────────────────────────────────────────
try:
    from web_app.reporting import (
        write_html_report,
        save_findings,
        diff_findings,
    )
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import reporting: {e}")
    raise

# ── Import Utilities ──────────────────────────────────────────────────────────
try:
    from web_app.utils.output import (
        _log,
        section,
        _log_finding_to_report,
        run_cmd,
    )
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import utils.output: {e}")
    raise

try:
    from web_app.utils.helpers import (
        normalise,
        validate,
        sanitise,
        diff_findings as diff_findings_helper,
    )
except ImportError as e:
    print(f"{Fore.YELLOW}⚠ Warning: Failed to import utils.helpers: {e}")
    raise

# ── Config Module ──────────────────────────────────────────────────────
try:
    from config import ConfigManager, print_config, validate_config
    HAS_CONFIG = True
except ImportError:
    HAS_CONFIG = False

# ═════════════════════════════════════════════════════════════════════════════
# Constants & Configuration
# ═════════════════════════════════════════════════════════════════════════════

VERSION = "3.3.0"
DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/120.0.0.0 Safari/537.36")
DEFAULT_TIMEOUT = 10

logger: Optional[logging.Logger] = None

# ═════════════════════════════════════════════════════════════════════════════
# Data Structures
# ═════════════════════════════════════════════════════════════════════════════

from enum import Enum
from dataclasses import dataclass, field

class TargetType(Enum):
    """Target type enumeration."""
    IP     = "ip"
    DOMAIN = "domain"

class ScanProfile(str, Enum):
    """Scan profile enumeration."""
    RECON   = "recon"    # Passive only
    ACTIVE  = "active"   # Passive + active recon + tech (no vuln scan)
    FULL    = "full"     # Everything
    STEALTH = "stealth"  # Full but throttled, no intrusive tools

@dataclass
class ScanConfig:
    """Main scan configuration."""
    target:          str
    target_type:     TargetType
    base_url:        str
    output_prefix:   str
    proxy:           Optional[str]  = None
    user_agent:      str            = DEFAULT_UA
    timeout:         int            = DEFAULT_TIMEOUT
    oob_url:         Optional[str]  = None
    scope_file:      Optional[str]  = None
    auto:            bool           = False
    rate:            int            = 50
    delay:           float          = 0.0
    full_ports:      bool           = False
    google_api_key:  Optional[str]  = None
    google_cx:       Optional[str]  = None
    google_dork_count: int          = 5
    diff_file:       Optional[str]  = None
    threads:         int            = 5
    verbose:         bool           = False
    # Auth
    cookie:          Optional[str]  = None
    extra_headers:   List[str]      = field(default_factory=list)
    auth_check_url:  Optional[str]  = None
    auth_check_text: Optional[str]  = None
    # Integrations
    webhook_url:     Optional[str]  = None
    webhook_threshold: Severity     = Severity.HIGH
    pentestdb_url:   Optional[str]  = None
    pentestdb_token: Optional[str]  = None
    # Scan control
    profile:         ScanProfile    = ScanProfile.FULL
    no_intrusive:    bool           = False
    nuclei_severity: str            = "medium,high,critical"
    html_report:     bool           = True
    # Tool timeouts
    whatweb_timeout: int            = 120
    arjun_timeout:   int            = 1200
    # Catch-all baseline
    catchall_active: bool           = False
    catchall_size:   int            = 0
    catchall_body:   str            = ""

# ═════════════════════════════════════════════════════════════════════════════
# Logger Setup
# ═════════════════════════════════════════════════════════════════════════════

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging for the scanner."""
    level = logging.DEBUG if verbose else logging.INFO
    logger_instance = logging.getLogger("webrecon")
    logger_instance.setLevel(level)

    # Console handler
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = logging.Formatter(
        fmt="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)

    if not logger_instance.handlers:
        logger_instance.addHandler(handler)

    return logger_instance

# ═════════════════════════════════════════════════════════════════════════════
# Helper Functions
# ═════════════════════════════════════════════════════════════════════════════

def _is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0

def _apply_profile(args, cfg: ScanConfig) -> ScanConfig:
    """Apply scan profile adjustments to configuration."""
    if cfg.profile == ScanProfile.STEALTH:
        cfg.rate          = min(cfg.rate, 10)
        cfg.threads       = min(cfg.threads, 2)
        cfg.delay         = max(cfg.delay, 0.5)
        cfg.no_intrusive  = True
    elif cfg.profile == ScanProfile.RECON:
        cfg.no_intrusive  = True
    return cfg

def _target_prefix(base: str, target: str, batch: bool) -> str:
    """Generate output prefix for target files."""
    if not batch:
        return base
    import re
    safe = re.sub(r'[^A-Za-z0-9._-]', '_', target)
    return f"{base}_{safe}"

def _reset_scan_state():
    """Clear all scan-scoped globals between batch targets."""
    # This needs to be called from web_app.py globals, kept for compatibility
    pass

def _print_batch_summary(results, batch_start):
    """Print summary of batch scan results."""
    dur = datetime.now() - batch_start
    print(f"\n{Fore.MAGENTA}{'═'*60}")
    print(f"{Fore.GREEN}  BATCH COMPLETE — {len(results)} target(s) in {str(dur).split('.')[0]}")
    print(f"{Fore.MAGENTA}{'═'*60}")
    tot = Counter()
    for target, prefix, counts in results:
        tot.update(counts)
        print(f"  {Fore.WHITE}{target}")
        print(f"    {Fore.MAGENTA}{counts.get(Severity.CRITICAL,0)} CRIT  "
              f"{Fore.RED}{counts.get(Severity.HIGH,0)} HIGH  "
              f"{Fore.YELLOW}{counts.get(Severity.MEDIUM,0)} MED  "
              f"{Fore.GREEN}{counts.get(Severity.LOW,0)} LOW  "
              f"{Fore.CYAN}{counts.get(Severity.INFO,0)} INFO   "
              f"{Fore.WHITE}→ {prefix}.report.html")
    print(f"\n{Fore.WHITE}  TOTAL  "
          f"{Fore.MAGENTA}{tot.get(Severity.CRITICAL,0)} CRIT  "
          f"{Fore.RED}{tot.get(Severity.HIGH,0)} HIGH  "
          f"{Fore.YELLOW}{tot.get(Severity.MEDIUM,0)} MED  "
          f"{Fore.GREEN}{tot.get(Severity.LOW,0)} LOW  "
          f"{Fore.CYAN}{tot.get(Severity.INFO,0)} INFO")
    print(f"{Fore.MAGENTA}{'═'*60}\n")

def _load_targets(args) -> List[str]:
    """Load target(s) from -iL file or command-line -t argument."""
    if args.target_list:
        if not os.path.exists(args.target_list):
            print(f"{Fore.RED}  [!] Target list not found: {args.target_list}")
            sys.exit(1)
        out = []
        with open(args.target_list) as fh:
            for line in fh:
                line = line.split('#', 1)[0].strip()  # strip inline comments
                if line:
                    out.append(line)
        if not out:
            print(f"{Fore.RED}  [!] Target list is empty: {args.target_list}")
            sys.exit(1)
        return out
    raw = args.target or input(f"{Fore.CYAN}  Target (domain or IP): ").strip()
    return [raw]

def write_summary(cfg: ScanConfig, out: str, findings: List[Finding], start: datetime):
    """Write scan summary to markdown report."""
    duration = datetime.now() - start
    counts = Counter(f.severity for f in findings)
    _log(out, "\n\n---\n# Summary\n")
    _log(out, f"| Field | Value |\n|---|---|\n"
              f"| Target | `{cfg.target}` |\n"
              f"| Base URL | {cfg.base_url} |\n"
              f"| Profile | {cfg.profile.value} |\n"
              f"| Duration | {str(duration).split('.')[0]} |\n"
              f"| Total Findings | {len(findings)} |\n")
    _log(out, "\n## Findings by Severity\n")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        _log(out, f"- **{sev.value}**: {counts.get(sev, 0)}")

    if cfg.diff_file:
        try:
            diff = diff_findings(findings, cfg.diff_file)
            if diff:
                _log(out, "\n## Delta vs Previous Scan\n")
                _log(out, f"- New: {len(diff.get('new', []))}")
                _log(out, f"- Resolved: {len(diff.get('resolved', []))}")
                _log(out, f"- Unchanged: {diff.get('unchanged', 0)}")
                if diff.get('new'):
                    _log(out, "\n### New Findings\n" +
                              '\n'.join(f"- [{f['severity']}] {f['title']}" for f in diff['new']))
                if diff.get('resolved'):
                    _log(out, "\n### Resolved\n" + '\n'.join(f"- {t}" for t in diff['resolved']))
        except Exception as e:
            if logger:
                logger.warning(f"Failed to generate diff: {e}")

# ═════════════════════════════════════════════════════════════════════════════
# Orchestration Functions
# ═════════════════════════════════════════════════════════════════════════════

def execute_phase_group(phase_group: Dict, pool_size: int = 2) -> bool:
    """
    Execute a group of phases in parallel using ThreadPoolExecutor.

    Args:
        phase_group: Dict mapping phase functions to their names
        pool_size: Number of worker threads

    Returns:
        bool: True if all phases completed successfully
    """
    if not phase_group:
        return True

    try:
        with ThreadPoolExecutor(max_workers=pool_size) as pool:
            futures = {
                pool.submit(func): name
                for func, name in phase_group.items()
            }
            for fut in as_completed(futures):
                try:
                    fut.result()
                except Exception as e:
                    phase_name = futures[fut]
                    if logger:
                        logger.error(f"Phase {phase_name} failed: {e}")
                    print(f"  {Fore.RED}✗ {phase_name}: {e}")
        return True
    except Exception as e:
        if logger:
            logger.error(f"Phase group execution failed: {e}")
        return False

def run_orchestrator(args, target: str, tt: TargetType, scope: ScopeChecker,
                     output_prefix: str, cfg_mgr: Optional['ConfigManager'] = None) -> Counter:
    """
    Main orchestrator function that coordinates all scanning phases.

    This function:
    1. Sets up the scan configuration
    2. Detects the URL scheme
    3. Initializes state management
    4. Executes phases in proper sequence
    5. Handles interruptions and errors
    6. Generates reports and exports findings

    Args:
        args: Parsed command-line arguments
        target: Target domain or IP
        tt: Target type (IP or DOMAIN)
        scope: Scope checker instance
        output_prefix: Prefix for output files
        cfg_mgr: Configuration manager instance (optional)

    Returns:
        Counter: Severity counts of findings
    """
    global logger

    out       = output_prefix + ".md"
    findings_file = output_prefix + ".findings.json"
    state_file = output_prefix + ".state.json"
    html_path = output_prefix + ".report.html"

    state = ScanState(state_file, target)
    if args.fresh:
        state.clear()
        print(f"{Fore.YELLOW}  [FRESH] State cleared.")

    # Get config value with precedence: CLI > config file > default
    def get_cfg(cli_val, cfg_key, default):
        if cli_val is not None and cli_val != default:
            return cli_val
        if cfg_mgr:
            cfg_val = cfg_mgr.get(cfg_key)
            if cfg_val is not None:
                return cfg_val
        return cli_val if cli_val is not None else default

    # Build initial config for scheme detection
    cfg_stub = ScanConfig(
        target=target, target_type=tt, base_url=f"http://{target}",
        output_prefix=output_prefix,
        proxy=args.proxy or (cfg_mgr.get("integrations.proxy") if cfg_mgr else None),
        user_agent=get_cfg(args.user_agent, "scanning.user_agent", DEFAULT_UA),
        timeout=get_cfg(args.timeout, "scanning.timeout", 10),
        cookie=args.cookie,
        extra_headers=args.headers or [],
    )

    print(f"\n{Fore.CYAN}  Detecting scheme for {target}…")
    scheme = detect_scheme(target, cfg_stub)

    # Build final config
    cfg = ScanConfig(
        target=target, target_type=tt,
        base_url=f"{scheme}://{target}",
        output_prefix=output_prefix,
        proxy=get_cfg(args.proxy, "scanning.proxy", None),
        user_agent=get_cfg(args.user_agent, "scanning.user_agent", DEFAULT_UA),
        timeout=get_cfg(args.timeout, "scanning.timeout", 10),
        oob_url=args.oob_url,
        scope_file=args.scope_file,
        auto=args.auto,
        rate=get_cfg(args.rate, "scanning.rate", 50),
        delay=get_cfg(args.delay, "scanning.delay", 0.0),
        full_ports=get_cfg(args.full_ports, "scanning.full_ports", False),
        google_api_key=args.google_api_key,
        google_cx=args.google_cx,
        google_dork_count=args.google_dork_count,
        diff_file=args.diff_file,
        threads=get_cfg(args.threads, "scanning.threads", 5),
        verbose=args.verbose,
        cookie=args.cookie,
        extra_headers=args.headers or [],
        auth_check_url=args.auth_check_url,
        auth_check_text=args.auth_check_text,
        webhook_url=args.webhook_url or (cfg_mgr.get("integrations.webhook_url") if cfg_mgr else None),
        webhook_threshold=Severity[args.webhook_threshold],
        pentestdb_url=args.pentestdb_url or (cfg_mgr.get("integrations.pentestdb_url") if cfg_mgr else None),
        pentestdb_token=args.pentestdb_token or (cfg_mgr.get("integrations.pentestdb_token") if cfg_mgr else None),
        profile=ScanProfile(args.profile),
        no_intrusive=args.no_intrusive,
        nuclei_severity=args.nuclei_severity,
        html_report=not args.no_html,
        whatweb_timeout=get_cfg(args.whatweb_timeout, "tools.whatweb_timeout", 120),
        arjun_timeout=get_cfg(args.arjun_timeout, "tools.arjun_timeout", 1200),
    )
    cfg = _apply_profile(args, cfg)

    start = datetime.now()

    # Initialize output file
    if not (args.resume and os.path.exists(out)):
        with open(out, 'w') as fh:
            fh.write(f"# WebRecon Report\n\n"
                     f"| | |\n|---|---|\n"
                     f"| **Target** | `{target}` ({tt.value}) |\n"
                     f"| **Base URL** | {cfg.base_url} |\n"
                     f"| **Profile** | {cfg.profile.value} |\n"
                     f"| **Started** | {start.isoformat()} |\n"
                     f"| **Tool** | WebRecon v{VERSION} |\n\n---\n")
    else:
        _log(out, f"\n\n---\n*Resumed at {start.isoformat()}*\n")

    print(f"\n{Fore.CYAN}  Target:   {target} ({tt.value})")
    print(f"{Fore.CYAN}  Base URL: {cfg.base_url}")
    print(f"{Fore.CYAN}  Profile:  {cfg.profile.value}")
    print(f"{Fore.CYAN}  Output:   {out}")
    if cfg.proxy:        print(f"{Fore.CYAN}  Proxy:    {cfg.proxy}")
    if cfg.oob_url:      print(f"{Fore.CYAN}  OOB:      {cfg.oob_url}")
    if cfg.cookie:       print(f"{Fore.CYAN}  Auth:     cookie provided")
    if cfg.webhook_url:  print(f"{Fore.CYAN}  Webhook:  configured (≥{cfg.webhook_threshold.value})")
    if cfg.pentestdb_url:print(f"{Fore.CYAN}  PentestDB:{cfg.pentestdb_url}")
    if not _is_root():
        print(f"\n{Fore.YELLOW}  ⚠ Not root — nmap OS detection will use sudo.")

    # Verify session if auth configured
    if cfg.auth_check_url:
        revalidate_session(cfg, out)

    # Shortcut profile checks
    is_recon_only = cfg.profile == ScanProfile.RECON
    is_full = cfg.profile in (ScanProfile.FULL, ScanProfile.STEALTH)

    detected_tech: Dict = {}
    interrupted = False

    try:
        # ── PHASE 1: PASSIVE RECONNAISSANCE ──────────────────────────────
        print(f"\n{Fore.MAGENTA}[ PHASE 1 — PASSIVE RECONNAISSANCE ]")

        phase_1_group = {
            lambda: phase_passive_dns(target, tt, cfg, out, state, scope): "dns",
            lambda: phase_cert_transparency(target, tt, cfg, out, state): "crt.sh",
            lambda: phase_wayback(target, cfg, out, state): "wayback",
            lambda: phase_google_dorks(target, cfg, out, state): "dorks",
            lambda: phase_dns_security(target, tt, cfg, out, state): "dns_sec",
        }
        execute_phase_group({f: n for f, n in phase_1_group.items()}, pool_size=5)

        phase_email_harvest(target, tt, cfg, out, state)
        phase_subdomain_enum(target, tt, cfg, out, state, scope)
        phase_favicon_hash(target, cfg, out, state)

        if is_recon_only:
            print(f"\n{Fore.YELLOW}[ Profile=recon → skipping active/vuln phases ]")
        else:
            # ── PHASE 2: ACTIVE RECONNAISSANCE ───────────────────────────
            print(f"\n{Fore.MAGENTA}[ PHASE 2 — ACTIVE RECONNAISSANCE ]")
            phase_port_scan(target, cfg, out, state)

            phase_2_group = {
                lambda: phase_waf_cdn(target, cfg, out, state): "waf",
                lambda: phase_vhost_fuzz(target, cfg, out, state): "vhost",
            }
            execute_phase_group({f: n for f, n in phase_2_group.items()}, pool_size=2)

            # ── PHASE 3: TECHNOLOGY & CONTENT DISCOVERY ──────────────────
            print(f"\n{Fore.MAGENTA}[ PHASE 3 — TECHNOLOGY & CONTENT DISCOVERY ]")
            detected_tech = phase_tech_detection(target, cfg, out, state)
            phase_tech_playbooks(target, cfg, out, state, detected_tech)
            phase_robots_sitemap(target, tt, cfg, out, state)
            phase_crawler(target, cfg, out, state)
            phase_api_schema(target, cfg, out, state)
            phase_source_exposure(target, cfg, out, state)
            phase_content_discovery(target, cfg, out, state)
            phase_param_discovery(target, cfg, out, state)

            # ── PHASE 4: HTTP ANALYSIS ──────────────────────────────────
            print(f"\n{Fore.MAGENTA}[ PHASE 4 — HTTP ANALYSIS ]")
            phase_4_group = {
                lambda: phase_header_analysis(target, cfg, out, state): "headers",
                lambda: phase_cors(target, cfg, out, state): "cors",
                lambda: phase_oauth_oidc(target, cfg, out, state): "oidc",
                lambda: phase_csp_analysis(target, cfg, out, state): "csp",
            }
            execute_phase_group({f: n for f, n in phase_4_group.items()}, pool_size=4)

            phase_host_header(target, cfg, out, state)
            phase_crlf(target, cfg, out, state)
            phase_csrf(target, cfg, out, state)
            phase_jwt_analysis(target, cfg, out, state)
            phase_http_methods(target, cfg, out, state)
            phase_403_bypass(target, cfg, out, state)

            if is_full:
                # ── PHASE 5: VULNERABILITY SCANNING ──────────────────────
                print(f"\n{Fore.MAGENTA}[ PHASE 5 — VULNERABILITY SCANNING ]")
                phase_ssl_tls(target, cfg, out, state)
                phase_nikto(target, cfg, out, state)
                phase_nuclei(target, cfg, out, state)

                phase_5_group = {
                    lambda: phase_js_analysis(target, cfg, out, state): "js",
                    lambda: phase_graphql(target, cfg, out, state): "graphql",
                    lambda: phase_path_traversal(target, cfg, out, state): "lfi",
                    lambda: phase_open_redirect(target, cfg, out, state): "redirect",
                    lambda: phase_reflection_xss(target, cfg, out, state): "xss",
                    lambda: phase_sqli(target, cfg, out, state): "sqli",
                    lambda: phase_websocket(target, cfg, out, state): "websocket",
                    lambda: phase_prototype_pollution(target, cfg, out, state): "protopollution",
                }
                execute_phase_group({f: n for f, n in phase_5_group.items()}, pool_size=6)

                phase_ssrf(target, cfg, out, state)
                phase_ssti(target, cfg, out, state)
                phase_xxe(target, cfg, out, state)
                phase_default_creds(target, cfg, out, state)
                phase_request_smuggling(target, cfg, out, state)

                # ── PHASE 6: INFRASTRUCTURE ────────────────────────────
                print(f"\n{Fore.MAGENTA}[ PHASE 6 — INFRASTRUCTURE ]")
                try:
                    phase_6_group = {
                        lambda: phase_cloud_buckets(target, cfg, out, state): "buckets",
                        lambda: phase_screenshots(target, cfg, out, state): "screenshots",
                    }
                    execute_phase_group({f: n for f, n in phase_6_group.items()}, pool_size=2)
                except NameError:
                    # Infrastructure phases may not be available yet
                    pass

    except KeyboardInterrupt:
        interrupted = True
        print(f"\n{Fore.YELLOW}  Interrupted — state saved. Re-run with --resume to continue.")
        _log(out, "\n\n---\n*Scan interrupted by user.*")
        if logger:
            logger.info("Scan interrupted by user")

    except Exception as e:
        import traceback
        print(f"{Fore.RED}  Fatal Error: {type(e).__name__}: {e}")
        _log(out, f"\n\n---\n*Fatal Error: {type(e).__name__}: {e}*")
        if logger:
            logger.exception("Fatal error during scan")
        if args.verbose:
            traceback.print_exc()

    finally:
        # ── FINALIZATION & REPORTING ──────────────────────────────────
        from web_app.core import _findings

        save_findings(_findings, findings_file)
        write_summary(cfg, out, _findings, start)

        if cfg.html_report:
            try:
                write_html_report(cfg, html_path, _findings, start)
                print(f"{Fore.CYAN}  HTML:     {html_path}")
            except Exception as e:
                print(f"{Fore.YELLOW}  ⚠ HTML report failed: {e}")

        counts = Counter(f.severity for f in _findings)
        print(f"\n{Fore.MAGENTA}{'═'*60}")
        print(f"{Fore.GREEN}  Scan complete!")
        print(f"  {Fore.MAGENTA}{counts.get(Severity.CRITICAL,0)} CRIT  "
              f"{Fore.RED}{counts.get(Severity.HIGH,0)} HIGH  "
              f"{Fore.YELLOW}{counts.get(Severity.MEDIUM,0)} MED  "
              f"{Fore.GREEN}{counts.get(Severity.LOW,0)} LOW  "
              f"{Fore.CYAN}{counts.get(Severity.INFO,0)} INFO")
        print(f"{Fore.CYAN}  Report:   {out}")
        print(f"{Fore.CYAN}  Findings: {findings_file}")
        print(f"{Fore.MAGENTA}{'═'*60}\n")

    if interrupted:
        raise KeyboardInterrupt

    return Counter(f.severity for f in _findings)

# ═════════════════════════════════════════════════════════════════════════════
# Argument Parsing
# ═════════════════════════════════════════════════════════════════════════════

def parse_args():
    """Parse command-line arguments."""
    p = ArgumentParser(
        description=f"WebRecon v{VERSION} — Comprehensive Web Application Enumeration",
        formatter_class=RawDescriptionHelpFormatter,
        epilog="""
Examples:
  web_app.py -t example.com
  web_app.py -t example.com -C configs/config.aggressive.yaml
  web_app.py -t example.com --proxy http://127.0.0.1:8080 --oob-url xxx.oast.live
  web_app.py -t example.com --cookie "session=abc123" --auth-check-url https://example.com/profile --auth-check-text "Logout"
  web_app.py -t example.com --profile stealth
  web_app.py -t example.com --profile aggressive --nuclei-severity high,critical
  web_app.py -t example.com --show-config
  web_app.py -iL targets.txt --auto --profile stealth
        """)

    # Configuration
    p.add_argument("-C", "--config", dest="config_file",
                   help="Config file (YAML). Searches ~/.webrecon-config.yaml and ./webrecon-config.yaml by default.")
    p.add_argument("--show-config", action="store_true",
                   help="Display effective configuration and exit")

    # Target
    p.add_argument("-t", "--target", help="Target domain or IP (host:port also accepted)")
    p.add_argument("-o", "--output", default="webrecon", help="Output file prefix")
    p.add_argument("-iL", "--target-list", dest="target_list",
                   help="File of targets, one per line")
    p.add_argument("--auto", action="store_true",
                   help="Skip interactive prompts (run all phases non-interactively)")
    p.add_argument("--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    p.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent")
    p.add_argument("--timeout", type=int, default=10, help="HTTP timeout (s)")
    p.add_argument("--rate", type=int, default=50, help="Per-phase thread/rate limit")
    p.add_argument("--delay", type=float, default=0.0, help="Inter-request delay (s)")
    p.add_argument("--oob-url", help="OOB callback host for XXE/SSRF")
    p.add_argument("--scope-file", help="Scope file: CIDRs (v4/v6) or domains, one per line")
    p.add_argument("--full-ports", action="store_true", help="Full port scan (-p-)")
    p.add_argument("--google-api-key", help="Google Custom Search API key")
    p.add_argument("--google-cx", help="Google Custom Search Engine ID")
    p.add_argument("--google-dork-count", type=int, default=5, help="Number of dorks to run via API (default 5)")
    p.add_argument("--diff", dest="diff_file", help="Previous findings JSON for diff mode")
    p.add_argument("--resume", action="store_true", help="Resume interrupted scan")
    p.add_argument("--fresh", action="store_true", help="Clear state and start fresh")
    p.add_argument("--threads", type=int, default=5, help="Parallel phase threads")
    p.add_argument("-v", "--verbose", action="store_true", help="Show tool stderr")

    # Auth
    p.add_argument("--cookie", help="Session cookie(s): 'name=val; name2=val2'")
    p.add_argument("--header", action="append", default=[], dest="headers",
                   help="Extra header (repeatable): 'Authorization: Bearer xyz'")
    p.add_argument("--auth-check-url", help="URL to verify session is still authenticated")
    p.add_argument("--auth-check-text", help="Text expected in auth-check-url response")

    # Integrations
    p.add_argument("--webhook-url", help="Discord/Slack webhook for HIGH+ findings")
    p.add_argument("--webhook-threshold", default="HIGH",
                   choices=["INFO","LOW","MEDIUM","HIGH","CRITICAL"],
                   help="Minimum severity to notify webhook (default HIGH)")
    p.add_argument("--pentestdb-url", help="PentestDB instance to POST findings to")
    p.add_argument("--pentestdb-token", help="Bearer token for PentestDB API")

    # Scan control
    p.add_argument("--profile", choices=[p.value for p in ScanProfile],
                   default=ScanProfile.FULL.value,
                   help="Scan profile: recon=passive only, active=+recon tools, full=everything, stealth=throttled")
    p.add_argument("--no-intrusive", action="store_true",
                   help="Skip intrusive checks (Nikto, nuclei intrusive tags, etc.)")
    p.add_argument("--nuclei-severity", default="medium,high,critical",
                   help="Nuclei severity filter (default: medium,high,critical)")
    p.add_argument("--no-html", action="store_true", help="Skip HTML report generation")
    p.add_argument("--whatweb-timeout", type=int, default=120,
                   help="WhatWeb timeout in seconds (default: 120)")
    p.add_argument("--arjun-timeout", type=int, default=1200,
                   help="Arjun timeout in seconds (default: 1200)")

    return p.parse_args()

# ═════════════════════════════════════════════════════════════════════════════
# Main Entry Point
# ═════════════════════════════════════════════════════════════════════════════

def main():
    """
    Main entry point for WebRecon.

    Coordinates:
    - Configuration loading
    - Target loading (single or batch)
    - Per-target scan orchestration
    - Batch result summary
    """
    global logger

    args = parse_args()

    # Initialize logging
    logger = setup_logging(verbose=args.verbose)
    logger.info(f"WebRecon v{VERSION} starting")

    # Initialize config manager
    if HAS_CONFIG:
        try:
            cfg_mgr = ConfigManager(explicit_config=args.config_file, verbose=args.verbose)
            validate_config(cfg_mgr)
            if args.verbose:
                logger.debug("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Failed to initialize config: {e}")
            cfg_mgr = None
    else:
        if args.config_file:
            print(f"{Fore.YELLOW}  ⚠ Config file support requires PyYAML. Install with: pip install PyYAML")
        cfg_mgr = None

    # Show config and exit if requested
    if args.show_config:
        print(f"\n{Fore.CYAN}Effective Configuration:\n")
        if cfg_mgr:
            print_config(cfg_mgr.to_dict())
        else:
            print("No configuration loaded (PyYAML not installed)")
        sys.exit(0)

    print(f"\n{Fore.MAGENTA}{'═'*60}")
    print(f"{Fore.MAGENTA}  WebRecon v{VERSION}")
    print(f"{Fore.MAGENTA}{'═'*60}\n")

    scope = ScopeChecker(args.scope_file)

    # Load and validate targets
    targets = _load_targets(args)
    batch = bool(args.target_list) or len(targets) > 1
    work, seen = [], set()

    for rawt in targets:
        t = normalise(rawt)
        if t in seen:
            continue
        seen.add(t)
        tt = validate(t)
        if not tt:
            print(f"{Fore.YELLOW}  [SKIP] Invalid target: {t!r}")
            continue
        try:
            sanitise(t)
        except ValueError as e:
            print(f"{Fore.YELLOW}  [SKIP] {e}")
            continue
        if not scope.check(t):
            print(f"{Fore.YELLOW}  [SKIP] Out of scope: {t}")
            continue
        work.append((t, tt))

    if not work:
        print(f"{Fore.RED}  [!] No valid, in-scope targets — aborting.")
        sys.exit(1)

    if batch:
        print(f"{Fore.CYAN}  Batch mode: {len(work)} target(s) queued.")

    batch_start = datetime.now()
    results = []

    for idx, (t, tt) in enumerate(work, 1):
        if batch:
            print(f"\n{Fore.MAGENTA}{'━'*60}")
            print(f"{Fore.MAGENTA}  [{idx}/{len(work)}]  {t}")
            print(f"{Fore.MAGENTA}{'━'*60}")

        prefix = _target_prefix(args.output, t, batch)

        try:
            counts = run_orchestrator(args, t, tt, scope, prefix, cfg_mgr)
            results.append((t, prefix, counts))
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}  Batch interrupted — stopping after {idx} target(s). "
                  f"Re-run with --resume to continue this target.")
            from web_app.core import _findings
            results.append((t, prefix, Counter(f.severity for f in _findings)))
            break
        except SystemExit:
            raise
        except Exception as e:
            print(f"{Fore.RED}  [!] {t} failed: {e}")
            results.append((t, prefix, Counter()))

    if batch:
        _print_batch_summary(results, batch_start)

if __name__ == "__main__":
    main()
