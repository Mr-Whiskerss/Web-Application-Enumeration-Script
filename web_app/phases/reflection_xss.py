"""
Reflected Input & XSS Context Analysis

Analysis of parameter reflection and XSS contexts:
- Reflected input detection via probe injection and response inspection
- XSS context identification (HTML body, attributes, JavaScript)
- Special character encoding detection for dangerous contexts
- Severity determination based on context and encoding patterns
"""

import os
import re
import hashlib
from typing import Set, TYPE_CHECKING
from urllib.parse import urlparse, parse_qs, quote

from web_app.core.session import make_session
from web_app.core.discovery import DISCOVERED
from web_app.core.findings import Finding, add_finding, Severity, _log_to_file
from web_app.core.state import ScanState

if TYPE_CHECKING:
    from web_app import ScanConfig


def _log(output_file: str, msg: str):
    """Log a message to the output file."""
    _log_to_file(output_file, msg)


def section(title: str, output_file: str):
    """Print and log a section header."""
    try:
        from colorama import Fore
    except ImportError:
        Fore = None

    sep = '─' * 55
    if Fore:
        print(f"\n{Fore.BLUE}{sep}")
        print(f"{Fore.BLUE}  {title}")
        print(f"{Fore.BLUE}{sep}")
    else:
        print(f"\n{sep}")
        print(f"  {title}")
        print(f"{sep}")

    _log(output_file, f"\n\n---\n# {title}\n")


def phase_reflection_xss(target: str, cfg: "ScanConfig", out: str, st: ScanState):
    phase = "reflection_xss"
    if st.done(phase): return
    section("Reflected Input / XSS Context Probe", out)
    sess = make_session(cfg)

    marker = "wrx" + hashlib.md5(os.urandom(6)).hexdigest()[:6]
    # Distinctive, non-executing probe. Special chars test output encoding.
    probe_chars = "<>\"'"
    probe = f"{marker}{probe_chars}{marker}"

    targets = DISCOVERED.get_urls_with_params(limit=40)
    # Also probe common params on the base URL
    common = ['q', 'search', 's', 'query', 'name', 'id', 'page', 'lang', 'redirect',
              'keyword', 'term', 'msg', 'message', 'ref', 'callback']
    base_targets = [f"{cfg.base_url}?{p}={probe}" for p in common]

    tested = 0
    reported_params: Set[str] = set()  # one report per (param) to avoid cross-source dupes
    for tgt in (targets + base_targets):
        if tested >= 60:
            break
        try:
            parsed = urlparse(tgt)
            qs = parse_qs(parsed.query)
            if not qs:
                continue
            # Replace each param's value with the probe, one at a time
            for pname in list(qs.keys()):
                if pname in reported_params:
                    continue
                newqs = {k: (probe if k == pname else v[0]) for k, v in qs.items()}
                # Encode values so they reach the server intact; the server decodes
                # them back to the raw chars, so an unescaped reflection is still
                # detectable — while other params with &/spaces no longer corrupt
                # the query. safe="<>\"'" keeps the probe chars readable in evidence.
                query = '&'.join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in newqs.items())
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query}"
                r = sess.get(test_url, timeout=cfg.timeout)
                tested += 1
                if marker not in r.text:
                    continue
                ctype = r.headers.get('Content-Type', '').lower()
                # Find what surrounds the marker
                idx = r.text.find(marker)
                window = r.text[max(0, idx - 1):idx + len(probe) + 1]
                lt_raw = "<" in window
                gt_raw = ">" in window
                quote_raw = ('"' in window) or ("'" in window)
                # Determine reflection context heuristically
                pre = r.text[max(0, idx - 60):idx].lower()
                if '<script' in pre and '</script>' not in pre:
                    context = "inside <script> (JS)"
                elif re.search(r'=\s*["\'][^"\']*$', r.text[max(0, idx-80):idx]):
                    context = "HTML attribute value"
                elif 'json' in ctype:
                    context = "JSON response"
                else:
                    context = "HTML body"

                reported_params.add(pname)
                if lt_raw and gt_raw:
                    sev = Severity.HIGH if 'json' not in ctype else Severity.LOW
                    add_finding(Finding(
                        title=f"Reflected Input — Unescaped `<>` via `{pname}`",
                        severity=sev,
                        description=(f"Parameter `{pname}` is reflected into the response in context "
                                     f"[{context}] with `<` and `>` UNescaped — strong XSS indicator. "
                                     f"(Probe was non-executing; confirm manually.)"),
                        evidence=f"URL: {test_url}\nContext: {context}\nReflected window: {window[:120]}",
                        recommendation="Context-aware output encoding (HTML-entity encode <,>,\",',&). Add a strong CSP as defence-in-depth.",
                        phase=phase), out, cfg)
                elif quote_raw and context in ("HTML attribute value", "inside <script> (JS)"):
                    add_finding(Finding(
                        title=f"Reflected Input — Unescaped Quote via `{pname}`",
                        severity=Severity.MEDIUM,
                        description=(f"Parameter `{pname}` is reflected into [{context}] with quote characters "
                                     f"unescaped — may allow breaking out of the current context."),
                        evidence=f"URL: {test_url}\nContext: {context}\nReflected window: {window[:120]}",
                        recommendation="Encode quotes for the relevant context; avoid reflecting input into attribute/JS contexts.",
                        phase=phase), out, cfg)
                else:
                    add_finding(Finding(
                        title=f"Parameter Reflection (encoded) via `{pname}`",
                        severity=Severity.INFO,
                        description=f"Parameter `{pname}` is reflected in [{context}] but special characters appear encoded.",
                        evidence=f"URL: {test_url}\nContext: {context}",
                        recommendation="No immediate action; reflection noted for manual review.",
                        phase=phase), out, cfg)
        except Exception:
            continue
    if tested == 0:
        _log(out, "> No parameterised URLs available to probe for reflection.")
    st.mark(phase)
