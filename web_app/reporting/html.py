"""
HTML Report Generation for WebRecon

This module handles the generation of interactive, filterable HTML reports
from scan findings. Reports include severity-based filtering, search functionality,
and a responsive dark-mode design with severity color coding.

Features:
  - Self-contained, single-file HTML output
  - Client-side filtering by severity level
  - Full-text search across findings
  - Expandable details for each finding
  - Severity-based color coding
  - Responsive grid layout for summary statistics
"""

from typing import List
from datetime import datetime
from collections import Counter
from dataclasses import dataclass


def write_html_report(cfg, html_path: str,
                       findings: List, start: datetime):
    """Emit a self-contained filterable HTML report.

    Generates an interactive HTML report with the following features:
    - Summary cards showing counts per severity level
    - Filterable table of findings with severity badges
    - Full-text search across all findings
    - Collapsible details for each finding (description, evidence, recommendation)
    - Responsive dark-mode design matching modern security dashboards

    Args:
        cfg: ScanConfig instance containing target, base_url, profile, and other scan metadata
        html_path: Path where the HTML report will be written
        findings: List of Finding objects to include in the report
        start: datetime when scan started (used for duration calculation)

    Returns:
        None (writes to html_path)
    """
    # Import here to avoid circular dependency
    from web_app.core.models import Severity

    # Severity ordering for sorting
    _SEV_ORDER = {Severity.INFO:0, Severity.LOW:1, Severity.MEDIUM:2,
                  Severity.HIGH:3, Severity.CRITICAL:4}

    duration = datetime.now() - start
    counts = Counter(f.severity for f in findings)
    rows = []
    for i, f in enumerate(sorted(findings, key=lambda x: -_SEV_ORDER[x.severity])):
        rows.append({
            "id": i, "title": f.title, "severity": f.severity.value,
            "description": f.description, "evidence": f.evidence,
            "recommendation": f.recommendation, "phase": f.phase,
            "timestamp": f.timestamp,
        })

    # Escape helper
    def esc(s):
        return (str(s).replace('&', '&amp;').replace('<', '&lt;')
                .replace('>', '&gt;').replace('"', '&quot;'))

    sev_colour = {
        "CRITICAL": "#8b0000", "HIGH": "#e74c3c", "MEDIUM": "#f39c12",
        "LOW":      "#27ae60", "INFO": "#3498db",
    }

    table_rows = ""
    for r in rows:
        c = sev_colour.get(r['severity'], '#555')
        table_rows += (
            f'<tr class="row" data-sev="{r["severity"]}">'
            f'<td><span class="badge" style="background:{c}">{r["severity"]}</span></td>'
            f'<td>{esc(r["title"])}</td>'
            f'<td>{esc(r["phase"])}</td>'
            f'<td><details><summary>show</summary>'
            f'<p><b>Description:</b> {esc(r["description"])}</p>'
            f'<pre>{esc(r["evidence"])}</pre>'
            f'<p><b>Recommendation:</b> {esc(r["recommendation"])}</p>'
            f'<p><i>Time:</i> {esc(r["timestamp"])}</p>'
            f'</details></td></tr>'
        )

    summary_cards = ""
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        c = sev_colour[sev.value]
        summary_cards += (f'<div class="card" style="border-left-color:{c}">'
                          f'<div class="sev">{sev.value}</div>'
                          f'<div class="num">{counts.get(sev, 0)}</div></div>')

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>WebRecon Report — {esc(cfg.target)}</title>
<style>
 * {{ box-sizing:border-box; }}
 body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
        margin:0; background:#0d1117; color:#c9d1d9; }}
 header {{ background:#161b22; padding:1.5rem 2rem; border-bottom:1px solid #30363d; }}
 h1 {{ margin:0; color:#58a6ff; }}
 .meta {{ color:#8b949e; font-size:.9rem; margin-top:.5rem; }}
 main {{ padding:2rem; max-width:1400px; margin:auto; }}
 .cards {{ display:grid; grid-template-columns:repeat(5, 1fr); gap:1rem; margin-bottom:2rem; }}
 .card {{ background:#161b22; padding:1rem; border-left:4px solid; border-radius:4px; }}
 .sev {{ font-size:.8rem; color:#8b949e; text-transform:uppercase; }}
 .num {{ font-size:2rem; font-weight:bold; color:#f0f6fc; }}
 .filters {{ margin-bottom:1rem; }}
 .filters button {{ background:#21262d; color:#c9d1d9; border:1px solid #30363d;
                   padding:.5rem 1rem; margin-right:.5rem; border-radius:4px; cursor:pointer; }}
 .filters button.active {{ background:#1f6feb; border-color:#1f6feb; color:white; }}
 input[type=text] {{ background:#0d1117; color:#c9d1d9; border:1px solid #30363d;
                    padding:.5rem; width:300px; border-radius:4px; }}
 table {{ width:100%; border-collapse:collapse; background:#161b22; border-radius:4px; overflow:hidden; }}
 th, td {{ padding:.75rem; text-align:left; border-bottom:1px solid #30363d; vertical-align:top; }}
 th {{ background:#21262d; color:#f0f6fc; font-weight:600; }}
 tr:hover {{ background:#1c2128; }}
 .badge {{ color:white; padding:.25rem .5rem; border-radius:3px; font-size:.75rem; font-weight:bold; }}
 pre {{ background:#0d1117; padding:.75rem; border-radius:4px; overflow:auto;
       white-space:pre-wrap; word-break:break-all; max-height:400px; }}
 details summary {{ cursor:pointer; color:#58a6ff; }}
 details[open] summary {{ margin-bottom:.5rem; }}
</style></head>
<body>
<header>
 <h1>WebRecon Report</h1>
 <div class="meta">
  <b>Target:</b> {esc(cfg.target)} &nbsp;|&nbsp;
  <b>Base URL:</b> {esc(cfg.base_url)} &nbsp;|&nbsp;
  <b>Profile:</b> {esc(cfg.profile.value)} &nbsp;|&nbsp;
  <b>Started:</b> {start.isoformat()} &nbsp;|&nbsp;
  <b>Duration:</b> {str(duration).split('.')[0]} &nbsp;|&nbsp;
  <b>Total:</b> {len(findings)} findings
 </div>
</header>
<main>
 <div class="cards">{summary_cards}</div>

 <div class="filters">
  <button class="filterbtn active" data-f="ALL">All</button>
  <button class="filterbtn" data-f="CRITICAL">Critical</button>
  <button class="filterbtn" data-f="HIGH">High</button>
  <button class="filterbtn" data-f="MEDIUM">Medium</button>
  <button class="filterbtn" data-f="LOW">Low</button>
  <button class="filterbtn" data-f="INFO">Info</button>
  <input type="text" id="search" placeholder="Search findings…">
 </div>

 <table>
  <thead><tr><th>Severity</th><th>Title</th><th>Phase</th><th>Details</th></tr></thead>
  <tbody>{table_rows}</tbody>
 </table>
</main>
<script>
 const btns = document.querySelectorAll('.filterbtn');
 const rows = document.querySelectorAll('tr.row');
 const search = document.getElementById('search');
 let activeFilter = 'ALL';
 function apply() {{
   const q = search.value.toLowerCase();
   rows.forEach(r => {{
     const sev = r.dataset.sev;
     const text = r.textContent.toLowerCase();
     const sevOk = activeFilter === 'ALL' || sev === activeFilter;
     const textOk = !q || text.includes(q);
     r.style.display = (sevOk && textOk) ? '' : 'none';
   }});
 }}
 btns.forEach(b => b.addEventListener('click', () => {{
   btns.forEach(x => x.classList.remove('active'));
   b.classList.add('active');
   activeFilter = b.dataset.f;
   apply();
 }}));
 search.addEventListener('input', apply);
</script>
</body></html>"""
    with open(html_path, 'w') as fh:
        fh.write(html)
