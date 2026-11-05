"""
Active Reconnaissance Phases

Proactive scanning that actively interacts with the target:
- Port scanning (nmap)
- WAF/CDN detection
- Virtual host fuzzing
"""

import os
from typing import List

from web_app.core.session import make_session
from web_app.core.findings import add_finding, Finding, Severity
from web_app.core.state import ScanState
from web_app.utils.logging import section
from web_app.utils.subprocess_runner import run_cmd
from web_app.utils.tool_check import _tool_ok, _sudo
from web_app.utils.output import _log
from web_app.core.config import ScanConfig


def phase_port_scan(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "port_scan"
    if st.done(phase): return
    section("Port Scanning (nmap)", out)
    if not _tool_ok("nmap", out):
        st.mark(phase); return

    host = target.split(':')[0]
    sp = _sudo()
    if cfg.full_ports:
        run_cmd(sp + ["nmap", "-vv", "-sV", "-Pn", "-p-", "--min-rate", "1000",
                      "-oA", f"/tmp/nmap_full_{host}", host],
                "Nmap full TCP scan", out, cfg, 2400)
    else:
        ports = ("21,22,23,25,53,80,81,88,110,143,389,443,445,465,587,636,993,995,"
                 "1080,1443,2049,3000,3306,3389,4443,4848,5000,5432,5900,6379,7001,"
                 "7443,8000,8080,8081,8443,8444,8888,9000,9090,9200,9443,10000,27017")
        run_cmd(sp + ["nmap", "-vv", "-sV", "-Pn", f"-p{ports}",
                      "-oA", f"/tmp/nmap_web_{host}", host],
                "Nmap web & common ports", out, cfg, 600)

    run_cmd(sp + ["nmap", "--script=http-methods", "-p", "80,443,8080,8443", host],
            "HTTP Methods NSE", out, cfg, 120)
    st.mark(phase)


def phase_waf_cdn(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "waf_cdn"
    if st.done(phase): return
    section("WAF / CDN Fingerprinting", out)

    if _tool_ok("wafw00f", out):
        stdout, _, _ = run_cmd(["wafw00f", cfg.base_url, "-a"], "wafw00f", out, cfg, 60)
        if stdout and ("is behind" in stdout.lower() or "detected" in stdout.lower()):
            add_finding(Finding(
                title="WAF Detected",
                severity=Severity.INFO,
                description="A Web Application Firewall was identified.",
                evidence=stdout[:500],
                recommendation="Note WAF type for bypass testing.",
                phase=phase), out, cfg)

    cdn_sigs = {
        "Cloudflare":    ["cf-ray", "cf-cache-status"],
        "AWS CloudFront":["x-amz-cf-id", "x-amz-cf-pop"],
        "Akamai":        ["x-akamai-transformed"],
        "Fastly":        ["x-fastly-request-id"],
        "Azure CDN":     ["x-msedge-ref"],
        "Sucuri":        ["x-sucuri-id"],
    }
    try:
        sess = make_session(cfg)
        r = sess.get(cfg.base_url, timeout=cfg.timeout)
        hdrs = {k.lower() for k in r.headers}
        found = [cdn for cdn, sigs in cdn_sigs.items() if any(s in hdrs for s in sigs)]
        if found:
            add_finding(Finding(
                title=f"CDN Detected: {', '.join(found)}",
                severity=Severity.INFO,
                description=f"Target is behind: {', '.join(found)}",
                evidence=str(dict(r.headers)),
                phase=phase), out, cfg)
    except Exception as e:
        _log(out, f"> CDN check failed: {e}")
    st.mark(phase)


def phase_vhost_fuzz(target: str, cfg: ScanConfig, out: str, st: ScanState):
    phase = "vhost_fuzz"
    if st.done(phase): return
    section("Virtual Host Fuzzing", out)

    if not _tool_ok("ffuf", out):
        st.mark(phase); return

    host = target.split(':')[0]
    candidates = [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt",
    ]
    wl = next((w for w in candidates if os.path.exists(w)), None)
    if not wl:
        _log(out, "> No wordlist found for vhost fuzzing."); st.mark(phase); return

    try:
        sess = make_session(cfg)
        r = sess.get(cfg.base_url, timeout=cfg.timeout)
        fs = str(len(r.content))
    except Exception:
        fs = "0"

    run_cmd(["ffuf", "-u", cfg.base_url, "-w", wl,
             "-H", f"Host: FUZZ.{host}",
             "-mc", "200,301,302,307,401,403",
             "-fs", fs, "-t", str(min(cfg.rate, 50)), "-timeout", "10"],
            "ffuf vhost fuzzing", out, cfg, 300)
    st.mark(phase)
