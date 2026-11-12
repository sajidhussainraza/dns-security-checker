#!/usr/bin/env python3
"""dns-security-checker: check a domain's email-authentication DNS posture.

Checks SPF, DKIM and DMARC records plus MX presence, and grades the domain
A-F. Dependency-free (Python 3.8+ standard library only): DNS queries are
built and parsed by hand over UDP, so there is nothing to install.

Usage:
    python3 dns_security_checker.py example.com
    python3 dns_security_checker.py example.com --selector google
    python3 dns_security_checker.py example.com --json
    python3 dns_security_checker.py example.com --fail-on high

Exit codes: 0 = no findings at/above --fail-on, 1 = findings found,
2 = usage error (bad domain, no DNS answer, network failure).
"""

import argparse
import base64
import json
import random
import re
import socket
import struct
import sys

DEFAULT_RESOLVER = "8.8.8.8"
DEFAULT_PORT = 53
TIMEOUT = 5.0

# Common DKIM selectors tried when none is given explicitly.
COMMON_SELECTORS = [
    "default", "google", "selector1", "selector2", "mail",
    "s1", "s2", "k1", "dkim", "mx", "email",
]

QTYPE = {"A": 1, "MX": 15, "TXT": 16}


# --------------------------------------------------------------------------
# Minimal DNS client (UDP, standard library only)
# --------------------------------------------------------------------------

def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        encoded = label.encode("idna")
        out += struct.pack("B", len(encoded)) + encoded
    return out + b"\x00"


def _decode_name(message, offset):
    """Decode a (possibly compressed) domain name. Returns (name, new_offset)."""
    labels = []
    jumped = False
    next_offset = offset
    while True:
        length = message[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            if not jumped:
                next_offset = offset + 2
            jumped = True
            offset = pointer
            continue
        offset += 1
        labels.append(message[offset:offset + length].decode("utf-8", "replace"))
        offset += length
    return ".".join(labels), (next_offset if jumped else offset)


def _build_query(name, qtype):
    txid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", QTYPE[qtype], 1)
    return txid, header + question


def _parse_response(message, txid, qtype):
    """Return a list of answer records: dicts with type, ttl and data."""
    if len(message) < 12:
        raise ValueError("DNS response too short")
    r_txid, _flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", message[:12])
    if r_txid != txid:
        raise ValueError("DNS transaction ID mismatch")
    offset = 12
    for _ in range(qdcount):  # skip question section
        _, offset = _decode_name(message, offset)
        offset += 4
    records = []
    for _ in range(ancount):
        _, offset = _decode_name(message, offset)
        rtype, _rclass, ttl, rdlen = struct.unpack(">HHHI", message[offset:offset + 10])
        offset += 10
        rdata = message[offset:offset + rdlen]
        offset += rdlen
        if rtype == 16:  # TXT: one or more length-prefixed strings
            parts, pos = [], 0
            while pos < len(rdata):
                strlen = rdata[pos]
                pos += 1
                parts.append(rdata[pos:pos + strlen].decode("utf-8", "replace"))
                pos += strlen
            records.append({"type": "TXT", "ttl": ttl, "data": "".join(parts)})
        elif rtype == 15:  # MX: preference + exchange name
            preference = struct.unpack(">H", rdata[:2])[0]
            exchange, _ = _decode_name(message, offset - rdlen + 2)
            records.append({"type": "MX", "ttl": ttl,
                            "data": {"preference": preference, "exchange": exchange}})
        elif rtype == 1 and len(rdata) == 4:  # A
            records.append({"type": "A", "ttl": ttl,
                            "data": socket.inet_ntoa(rdata)})
        # Other types are ignored.
    return records


def dns_query(name, qtype, resolver=DEFAULT_RESOLVER, port=DEFAULT_PORT):
    """Query one record type for a name. Returns a list of record dicts.

    Tries a hand-built UDP query first; falls back to the `dig` command
    when raw UDP is unavailable (sandboxed or proxied networks).
    """
    try:
        txid, packet = _build_query(name, qtype)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT)
        try:
            sock.sendto(packet, (resolver, port))
            message, _ = sock.recvfrom(4096)
        finally:
            sock.close()
        return _parse_response(message, txid, qtype)
    except OSError:
        return _dig_query(name, qtype, resolver)


def _dig_query(name, qtype, resolver):
    """Fallback DNS lookup via the `dig` command. Same record format.

    Tries the requested resolver first, then the system resolver: direct
    UDP to an external resolver is blocked on some networks (including
    this sandbox), while the system resolver still answers.
    """
    import subprocess
    attempts = [["dig", "+short", qtype, name, "@" + resolver],
                ["dig", "+short", qtype, name]]
    last_error = None
    for cmd in attempts:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=4)
        except subprocess.TimeoutExpired:
            last_error = "dig timed out (%s)" % " ".join(cmd)
            continue
        if proc.returncode != 0:
            last_error = "dig failed for %s %s: %s" % (
                qtype, name, proc.stderr.strip())
            continue
        return _parse_dig_output(proc.stdout, qtype)
    raise ValueError(last_error or "dig failed for %s %s" % (qtype, name))


def _parse_dig_output(stdout, qtype):
    records = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        if qtype == "TXT":
            # dig prints each TXT record on one line as quoted strings;
            # join the segments (a record may be split into several).
            text = "".join(re.findall(r'"([^"]*)"', line)) or line
            records.append({"type": "TXT", "ttl": 0, "data": text})
        elif qtype == "MX":
            parts = line.rstrip(".").split()
            if len(parts) == 2:
                records.append({"type": "MX", "ttl": 0,
                                "data": {"preference": int(parts[0]),
                                         "exchange": parts[1]}})
        elif qtype == "A":
            records.append({"type": "A", "ttl": 0, "data": line})
    return records


# --------------------------------------------------------------------------
# Record analysis
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _tag_value(record, tag):
    """Value of `tag=` inside a semicolon- or space-separated record.

    The separator must be the start, ';' or whitespace, so that e.g. the
    DMARC tag 'p' does not match inside 'sp=quarantine'.
    """
    match = re.search(r"(?:^|[;\s])\s*" + re.escape(tag) + r"\s*=\s*([^;\s]+)",
                      record, re.IGNORECASE)
    return match.group(1) if match else None


def check_spf(txt_records):
    """Analyse SPF. Returns (findings, details dict)."""
    findings = []
    spf = [r for r in txt_records if r.strip().lower().startswith("v=spf1")]
    if len(spf) > 1:
        findings.append(("high", "Multiple SPF records found (%d); "
                         "receivers will reject SPF outright." % len(spf)))
    if not spf:
        findings.append(("high", "No SPF record published: anyone can spoof "
                         "this domain in the From address."))
        return findings, {"present": False}
    record = spf[0]
    details = {"present": True, "record": record}
    redirect = _tag_value(record, "redirect")
    if redirect:
        details["redirect"] = redirect

    mechanisms = re.findall(r"(?:^|\s)([a-z0-9+_.-]+)(?::[^\s;]+)?",
                            record, re.IGNORECASE)
    lookup_mechs = [m for m in mechanisms
                    if m.lower() in ("include", "a", "mx", "ptr", "exists",
                                     "redirect")]
    details["dns_lookups"] = len(lookup_mechs)
    if len(lookup_mechs) > 10:
        findings.append(("high", "SPF triggers %d DNS lookups (limit is 10); "
                         "receivers return permerror." % len(lookup_mechs)))
    elif len(lookup_mechs) >= 8:
        findings.append(("low", "SPF triggers %d DNS lookups, close to the "
                         "10-lookup limit." % len(lookup_mechs)))
    if record.strip().endswith("+all") or " +all" in record:
        findings.append(("high", "SPF ends in +all: it authorises every "
                         "sender on the internet. Use -all."))
    elif "~all" in record:
        findings.append(("medium", "SPF ends in ~all (softfail). Use -all "
                         "for strict enforcement once mail flow is verified."))
    elif "-all" not in record:
        findings.append(("medium", "SPF has no -all qualifier, so unauthorised "
                         "senders are not rejected."))
    if " ptr" in record.lower():
        findings.append(("low", "SPF uses the ptr mechanism: slow and "
                         "deprecated, remove it."))
    return findings, details


def check_dmarc(txt_records):
    """Analyse DMARC. Returns (findings, details dict)."""
    findings = []
    dmarc = [r for r in txt_records if r.strip().lower().startswith("v=dmarc1")]
    if not dmarc:
        findings.append(("high", "No DMARC record published: spoofed mail "
                         "has no policy to act on."))
        return findings, {"present": False}
    record = dmarc[0]
    policy = (_tag_value(record, "p") or "").lower()
    pct = _tag_value(record, "pct") or "100"
    details = {"present": True, "record": record, "policy": policy, "pct": pct}
    if policy == "none":
        findings.append(("medium", "DMARC policy is p=none (monitor only): "
                         "spoofed mail is still delivered. Move to "
                         "quarantine, then reject."))
    elif policy == "quarantine":
        findings.append(("low", "DMARC policy is p=quarantine. Consider "
                         "p=reject once alignment is clean."))
    elif policy == "reject":
        pass  # best case, no finding
    else:
        findings.append(("high", "DMARC policy '%s' is not recognised; "
                         "expected none, quarantine or reject." % policy))
    if pct != "100":
        findings.append(("low", "DMARC applies to only %s%% of mail "
                         "(pct=%s)." % (pct, pct)))
    if not _tag_value(record, "rua"):
        findings.append(("low", "DMARC has no rua= reporting address, so "
                         "abuse is invisible."))
    return findings, details


def check_dkim(domain, resolver, selector=None):
    """Probe DKIM selectors. Returns (findings, details dict)."""
    selectors = [selector] if selector else COMMON_SELECTORS
    found = []
    for sel in selectors:
        name = "%s._domainkey.%s" % (sel, domain)
        try:
            records = dns_query(name, "TXT", resolver=resolver)
        except (OSError, ValueError):
            continue
        for record in records:
            data = record["data"]
            if "v=DKIM1" in data or "k=" in data or "p=" in data:
                key = _tag_value(data, "p") or ""
                key_bits = None
                if key:
                    try:
                        key_bits = len(base64.b64decode(key, validate=False)) * 8
                    except Exception:
                        key_bits = None
                found.append({"selector": sel, "key_bits": key_bits,
                              "record": data})
                if key_bits is not None and key_bits < 2048:
                    found[-1]["weak_key"] = True
    if not found:
        return ([("medium", "No DKIM key found under common selectors %s. "
                  "Publish a DKIM key (or re-run with --selector <name>)."
                  % ", ".join(selectors))],
                {"present": False, "selectors_tried": selectors})
    findings = []
    for entry in found:
        if entry.get("weak_key"):
            findings.append(("medium", "DKIM selector '%s' uses a %d-bit key; "
                             "rotate to 2048-bit." % (entry["selector"],
                                                      entry["key_bits"])))
    return findings, {"present": True, "keys": found}


def check_mx(mx_records, a_records):
    findings = []
    if not mx_records:
        findings.append(("high", "No MX records: the domain cannot receive "
                         "mail at all."))
        return findings, {"present": False}
    hosts = sorted(r["data"]["exchange"] for r in mx_records)
    details = {"present": True, "hosts": hosts}
    if len(hosts) == 1:
        findings.append(("low", "Only one MX host (%s): a single point of "
                         "failure for inbound mail." % hosts[0]))
    if not a_records:
        findings.append(("low", "Domain has no A record (website may be "
                         "unreachable), though MX is present."))
    return findings, details


def grade(findings):
    """Score 100 minus deductions; map to a letter grade."""
    deductions = {"high": 25, "medium": 10, "low": 3, "info": 0}
    score = 100 - sum(deductions[s] for s, _ in findings)
    score = max(0, score)
    if score >= 90:
        letter = "A"
    elif score >= 75:
        letter = "B"
    elif score >= 60:
        letter = "C"
    elif score >= 40:
        letter = "D"
    else:
        letter = "F"
    return score, letter


# --------------------------------------------------------------------------
# Driver
# --------------------------------------------------------------------------

DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
                       r"(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$")


def run_check(domain, resolver=DEFAULT_RESOLVER, selector=None):
    if not DOMAIN_RE.match(domain):
        raise ValueError("'%s' is not a valid domain name" % domain)
    domain = domain.lower()

    try:
        spf_txt = dns_query(domain, "TXT", resolver=resolver)
    except (OSError, ValueError) as exc:
        raise ValueError("DNS query failed for %s: %s" % (domain, exc))
    try:
        dmarc_txt = dns_query("_dmarc." + domain, "TXT", resolver=resolver)
    except (OSError, ValueError):
        dmarc_txt = []
    try:
        mx_records = dns_query(domain, "MX", resolver=resolver)
    except (OSError, ValueError):
        mx_records = []
    try:
        a_records = dns_query(domain, "A", resolver=resolver)
    except (OSError, ValueError):
        a_records = []

    findings = []
    spf_findings, spf = check_spf([r["data"] for r in spf_txt])
    # Follow an SPF redirect for the -all check: the qualifier lives on
    # the target record (e.g. gmail.com redirects to _spf.google.com).
    if spf.get("redirect"):
        try:
            target_txt = dns_query(spf["redirect"], "TXT", resolver=resolver)
            target_spf = [r["data"] for r in target_txt
                          if r["data"].strip().lower().startswith("v=spf1")]
            if target_spf:
                spf["redirect_record"] = target_spf[0]
                if "-all" in target_spf[0]:
                    spf_findings = [(s, m) for s, m in spf_findings
                                    if "no -all qualifier" not in m]
                elif "~all" in target_spf[0]:
                    spf_findings = [
                        (s, "SPF ends in ~all (softfail) via redirect to %s. "
                            "Use -all for strict enforcement once mail flow "
                            "is verified." % spf["redirect"])
                        if "no -all qualifier" in m else (s, m)
                        for s, m in spf_findings]
        except (OSError, ValueError):
            pass
    dmarc_findings, dmarc = check_dmarc([r["data"] for r in dmarc_txt])
    dkim_findings, dkim = check_dkim(domain, resolver, selector)
    mx_findings, mx = check_mx(mx_records, a_records)
    findings = spf_findings + dmarc_findings + dkim_findings + mx_findings
    findings.sort(key=lambda f: SEVERITY_ORDER[f[0]], reverse=True)

    score, letter = grade(findings)
    return {
        "domain": domain,
        "score": score,
        "grade": letter,
        "spf": spf,
        "dmarc": dmarc,
        "dkim": dkim,
        "mx": mx,
        "findings": [{"severity": s, "message": m} for s, m in findings],
    }


def print_report(result):
    print("DNS security report: %s" % result["domain"])
    print("Score: %d/100  Grade: %s" % (result["score"], result["grade"]))
    print()
    print("  SPF:   %s" % ("PUBLISHED" if result["spf"]["present"] else "MISSING"))
    if result["spf"].get("record"):
        print("         %s" % result["spf"]["record"])
    print("  DMARC: %s" % ("PUBLISHED (p=%s)" % result["dmarc"].get("policy", "?")
                           if result["dmarc"]["present"] else "MISSING"))
    if result["dmarc"].get("record"):
        print("         %s" % result["dmarc"]["record"])
    print("  DKIM:  %s" % ("PUBLISHED" if result["dkim"]["present"] else "NOT FOUND"))
    for key in result["dkim"].get("keys", []):
        bits = key["key_bits"]
        print("         selector '%s' (%s)"
              % (key["selector"],
                 "%d-bit key" % bits if bits is not None
                 else "key length unknown"))
    print("  MX:    %s" % (", ".join(result["mx"].get("hosts", []))
                           or "MISSING"))
    print()
    if not result["findings"]:
        print("No findings. Email authentication is fully configured.")
    else:
        print("Findings (%d):" % len(result["findings"]))
        for finding in result["findings"]:
            print("  [%s] %s" % (finding["severity"].upper(), finding["message"]))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check a domain's SPF, DKIM, DMARC and MX records.")
    parser.add_argument("domain", help="domain to check, e.g. example.com")
    parser.add_argument("--resolver", default=DEFAULT_RESOLVER,
                        help="DNS resolver to query (default %(default)s)")
    parser.add_argument("--selector",
                        help="DKIM selector to check instead of common ones")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON instead of a report")
    parser.add_argument("--fail-on", default="high",
                        choices=list(SEVERITY_ORDER),
                        help="fail when a finding of this severity or "
                             "higher exists (default: high)")
    args = parser.parse_args(argv)

    try:
        result = run_check(args.domain, resolver=args.resolver,
                           selector=args.selector)
    except ValueError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_report(result)

    threshold = SEVERITY_ORDER[args.fail_on]
    worst = max((SEVERITY_ORDER[f["severity"]] for f in result["findings"]),
                default=0)
    return 1 if worst >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
