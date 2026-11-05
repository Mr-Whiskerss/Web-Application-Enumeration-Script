"""
SQL Injection Detection Phase

Differential SQL injection detection featuring:
- Error-based SQLi detection via database error message matching
- Boolean-based blind SQLi detection via response differential analysis
- Time-based blind SQLi confirmation with SLEEP/pg_sleep payloads
- Stability guard to prevent false positives on dynamic content
- Multi-database support: MySQL, MSSQL, PostgreSQL, SQLite, Oracle
"""

import re
import time
from urllib.parse import urlparse, parse_qs, quote
from typing import TYPE_CHECKING

from web_app.core.session import make_session
from web_app.core.findings import add_finding, Finding, Severity
from web_app.core.state import ScanState
from web_app.core.discovery import DISCOVERED

if TYPE_CHECKING:
    from web_app import ScanConfig


def section(title: str, output_file: str):
    """Print and log a section header."""
    print(f"\n{title}")
    with open(output_file, 'a') as fh:
        fh.write(f"\n\n---\n# {title}\n")


def _log(output_file: str, msg: str):
    """Append a message to the output file."""
    with open(output_file, 'a') as fh:
        fh.write(msg + '\n')

# SQL error patterns matching various databases
_SQL_ERRORS = [
    r"you have an error in your sql syntax",
    r"warning:\s+mysqli?_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg_exec\(\)|postgresql.*error",
    r"sqlite_error|sqlite3::|near \".*\": syntax error",
    r"ora-\d{5}",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"system\.data\.sqlclient\.sqlexception",
    r"org\.hibernate\.|javax\.persistence",
]


def phase_sqli(target: str, cfg: "ScanConfig", out: str, st: ScanState):
    """Differential SQLi detection. Time-based confirmation only runs when
    intrusive checks are permitted (it sends SLEEP/pg_sleep payloads)."""
    phase = "sqli"
    if st.done(phase): return
    section("SQL Injection Probe", out)
    sess = make_session(cfg)

    targets = DISCOVERED.get_urls_with_params(limit=30)
    if not targets:
        _log(out, "> No parameterised URLs available for SQLi testing.")
        st.mark(phase); return

    err_re = re.compile('|'.join(_SQL_ERRORS), re.I)

    for tgt in targets:
        try:
            parsed = urlparse(tgt)
            qs = parse_qs(parsed.query)
        except Exception:
            continue
        if not qs:
            continue

        for pname, pvals in qs.items():
            orig = pvals[0] if pvals else "1"

            def build(value: str) -> str:
                # Percent-encode every value so payloads containing spaces/quotes
                # reach the server intact instead of being mangled or rejected
                # (raw concatenation was a silent source of false negatives).
                nq = {k: (value if k == pname else v[0]) for k, v in qs.items()}
                q = '&'.join(f"{quote(k, safe='')}={quote(v, safe='')}" for k, v in nq.items())
                return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{q}"

            # ── Error-based ──
            try:
                er = sess.get(build(orig + "'\""), timeout=cfg.timeout)
                if err_re.search(er.text):
                    add_finding(Finding(
                        title=f"SQL Injection (error-based) via `{pname}`",
                        severity=Severity.CRITICAL,
                        description=f"Injecting a quote into `{pname}` produced a database error message.",
                        evidence=f"URL: {build(orig + chr(39) + chr(34))}\nMatched DB error in response.",
                        recommendation="Use parameterised queries / prepared statements. Never concatenate user input into SQL.",
                        phase=phase), out, cfg)
                    continue  # confirmed; move to next param
            except Exception:
                pass

            # ── Boolean-based differential ──
            try:
                base = sess.get(build(orig), timeout=cfg.timeout)
                # Stability guard: fetch the SAME baseline a second time. If the
                # page isn't stable (rotating CSRF token, timestamp, ad slot, etc.)
                # length-based boolean inference is unreliable — skip it to avoid
                # false positives.
                base2 = sess.get(build(orig), timeout=cfg.timeout)
                lb, lb2 = len(base.text), len(base2.text)
                page_stable = abs(lb - lb2) < max(40, lb * 0.02)
                if not page_stable:
                    _log(out, f"> `{pname}`: baseline unstable "
                              f"({lb}B vs {lb2}B) — skipping boolean-based SQLi to avoid FP.")
                else:
                    true_url  = build(f"{orig}' AND '1'='1")
                    false_url = build(f"{orig}' AND '1'='2")
                    tr = sess.get(true_url, timeout=cfg.timeout)
                    fr = sess.get(false_url, timeout=cfg.timeout)
                    lt, lf = len(tr.text), len(fr.text)
                    # TRUE should resemble baseline; FALSE should differ markedly
                    true_like_base = abs(lt - lb) < max(40, lb * 0.02)
                    false_differs  = abs(lf - lt) > max(60, lt * 0.05)
                    if tr.status_code == fr.status_code == 200 and true_like_base and false_differs:
                        add_finding(Finding(
                            title=f"SQL Injection (boolean-based) via `{pname}`",
                            severity=Severity.HIGH,
                            description=(f"Parameter `{pname}` shows boolean-differential behaviour: the TRUE "
                                         f"condition matches the baseline page while the FALSE condition diverges."),
                            evidence=(f"baseline={lb}B  TRUE(1=1)={lt}B  FALSE(1=2)={lf}B\n"
                                      f"TRUE:  {true_url}\nFALSE: {false_url}"),
                            recommendation="Use parameterised queries. Validate/whitelist input types.",
                            phase=phase), out, cfg)
                        continue
            except Exception:
                pass

            # ── Time-based confirmation (intrusive only) ──
            if not cfg.no_intrusive:
                try:
                    # Baseline latency (median of 2)
                    t0 = time.time(); sess.get(build(orig), timeout=cfg.timeout + 8); base_lat = time.time() - t0
                    payloads = [
                        f"{orig}' AND SLEEP(5)-- -",            # MySQL
                        f"{orig}'; WAITFOR DELAY '0:0:5'-- -",   # MSSQL
                        f"{orig}' AND pg_sleep(5)-- -",          # PostgreSQL
                    ]
                    for pl in payloads:
                        t0 = time.time()
                        sess.get(build(pl), timeout=cfg.timeout + 8)
                        delay = time.time() - t0
                        if delay > base_lat + 4:
                            # Confirm with a second, longer sleep to rule out jitter
                            confirm_pl = pl.replace("(5)", "(8)").replace("0:0:5", "0:0:8")
                            t0 = time.time(); sess.get(build(confirm_pl), timeout=cfg.timeout + 12)
                            delay2 = time.time() - t0
                            if delay2 > base_lat + 7:
                                add_finding(Finding(
                                    title=f"SQL Injection (time-based blind) via `{pname}`",
                                    severity=Severity.CRITICAL,
                                    description=f"Parameter `{pname}` shows a time delay tracking an injected SLEEP — blind SQLi.",
                                    evidence=(f"baseline≈{base_lat:.1f}s  5s-payload≈{delay:.1f}s  "
                                              f"8s-confirm≈{delay2:.1f}s\nPayload: {pl}"),
                                    recommendation="Use parameterised queries. This is exploitable blind SQLi — prioritise remediation.",
                                    phase=phase), out, cfg)
                                break
                except Exception:
                    pass
    st.mark(phase)
