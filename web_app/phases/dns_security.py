"""
DNS Security Posture Analysis

Passive DNS security evaluation:
- SPF record analysis
- DMARC policy checking
- DNSSEC validation
- CAA record verification
- Zone transfer (AXFR) testing
"""

import re
import shutil
import subprocess
from typing import List

from web_app.core.findings import Finding, Severity, add_finding
from web_app.core.state import ScanState


def _dig(args: List[str], timeout: int = 10) -> str:
	"""Thin dig wrapper. Returns stdout ('' on any failure)."""
	if not shutil.which("dig"):
		return ""
	try:
		r = subprocess.run(["dig", "+short"] + args,
						   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
						   text=True, timeout=timeout)
		return r.stdout.strip()
	except Exception:
		return ""


def phase_dns_security(target, tt, cfg, out: str, st: ScanState):
	"""Passive DNS hardening review: SPF, DMARC, DNSSEC, CAA, plus an
	AXFR zone-transfer attempt against each authoritative nameserver."""
	# Import here to avoid circular dependencies and late binding
	from .. import section, _log, TargetType

	phase = "dns_security"
	if st.done(phase) or tt != TargetType.DOMAIN:
		return
	section("DNS Security Posture (SPF / DMARC / DNSSEC / CAA / AXFR)", out)
	if not shutil.which("dig"):
		_log(out, "> dig not installed — skipping DNS security checks.")
		st.mark(phase)
		return

	host = target.split(':')[0]

	# SPF
	spf = [l for l in _dig(["TXT", host]).splitlines() if 'v=spf1' in l.lower()]
	if not spf:
		add_finding(Finding(
			title="Missing SPF Record",
			severity=Severity.LOW,
			description="No SPF (v=spf1) TXT record found — eases email spoofing of this domain.",
			evidence=f"dig +short TXT {host} → no v=spf1",
			recommendation="Publish an SPF record ending in `-all` (hard fail) once senders are enumerated.",
			phase=phase), out, cfg)
	else:
		joined = ' '.join(spf).lower()
		_log(out, f"- SPF: `{spf[0][:300]}`")
		if '+all' in joined or ('~all' not in joined and '-all' not in joined):
			add_finding(Finding(
				title="Weak SPF Policy",
				severity=Severity.LOW,
				description="SPF record uses `+all`/`?all` or omits an `all` mechanism — does not restrict senders.",
				evidence=spf[0][:300],
				recommendation="Terminate the SPF record with `-all` (or at minimum `~all`).",
				phase=phase), out, cfg)

	# DMARC
	dmarc = [l for l in _dig(["TXT", f"_dmarc.{host}"]).splitlines() if 'v=dmarc1' in l.lower()]
	if not dmarc:
		add_finding(Finding(
			title="Missing DMARC Record",
			severity=Severity.MEDIUM,
			description="No DMARC record at _dmarc — receivers have no policy for SPF/DKIM failures, enabling spoofing.",
			evidence=f"dig +short TXT _dmarc.{host} → empty",
			recommendation="Publish a DMARC record, starting at `p=none` for monitoring then moving to `p=quarantine`/`p=reject`.",
			phase=phase), out, cfg)
	else:
		rec = dmarc[0].lower()
		_log(out, f"- DMARC: `{dmarc[0][:300]}`")
		if 'p=none' in rec:
			add_finding(Finding(
				title="DMARC Policy Not Enforced (p=none)",
				severity=Severity.LOW,
				description="DMARC is published but set to `p=none` — failures are only monitored, not blocked.",
				evidence=dmarc[0][:300],
				recommendation="Progress the policy to `p=quarantine` then `p=reject` after monitoring reports.",
				phase=phase), out, cfg)

	# DNSSEC
	dnskey = _dig(["DNSKEY", host])
	if not dnskey:
		add_finding(Finding(
			title="DNSSEC Not Enabled",
			severity=Severity.INFO,
			description="No DNSKEY records — the zone is not DNSSEC-signed and is exposed to DNS spoofing/cache poisoning.",
			evidence=f"dig +short DNSKEY {host} → empty",
			recommendation="Enable DNSSEC signing at the registrar/DNS provider where feasible.",
			phase=phase), out, cfg)
	else:
		_log(out, "- DNSSEC: DNSKEY present (zone signed)")

	# CAA
	caa = _dig(["CAA", host])
	if not caa:
		add_finding(Finding(
			title="No CAA Record",
			severity=Severity.INFO,
			description="No CAA record — any CA may issue certificates for this domain.",
			evidence=f"dig +short CAA {host} → empty",
			recommendation="Publish a CAA record restricting issuance to approved CAs.",
			phase=phase), out, cfg)
	else:
		_log(out, f"- CAA: `{caa[:200]}`")

	# Zone transfer (AXFR) against each NS
	nameservers = [n.rstrip('.') for n in _dig(["NS", host]).splitlines() if n.strip()]
	_log(out, f"- Nameservers: {', '.join(nameservers) or 'none resolved'}")
	for ns in nameservers[:6]:
		try:
			r = subprocess.run(["dig", f"@{ns}", host, "AXFR", "+time=5", "+tries=1"],
							   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
							   text=True, timeout=15)
			body = r.stdout
			# A real transfer dumps many records; failures say "Transfer failed"/"connection timed out"
			if "Transfer failed" not in body and "connection timed out" not in body \
			   and body.count("IN") >= 5 and "SOA" in body:
				add_finding(Finding(
					title=f"DNS Zone Transfer Allowed: {ns}",
					severity=Severity.HIGH,
					description=f"Nameserver {ns} permits AXFR zone transfer, leaking the full DNS zone for {host}.",
					evidence=f"dig @{ns} {host} AXFR returned {body.count(chr(10))} lines\n{body[:600]}",
					recommendation="Restrict AXFR to authorised secondaries only (allow-transfer ACL).",
					phase=phase), out, cfg)
				# Mine transferred A/CNAME hostnames into DISCOVERED context
				hosts = re.findall(r'^(\S+?)\.\s+\d+\s+IN\s+(?:A|AAAA|CNAME)', body, re.M)
				if hosts:
					_log(out, f"  → {len(hosts)} hostnames recovered from zone transfer")
		except Exception:
			continue
	st.mark(phase)
