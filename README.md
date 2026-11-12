# DNS Security Checker

A small, dependency-free Python CLI that audits a domain's email
authentication posture: SPF, DKIM, DMARC and MX records. It grades the
domain A-F and explains each finding in plain language, so students and
small teams can see exactly why their mail is spoofable and how to fix it.

No dependencies, no network calls beyond DNS: everything runs locally on
your own machine. DNS queries are built and parsed by hand over UDP
(standard library only); when raw UDP is unavailable the tool falls back
to the `dig` command.

## What it checks

| Check | What a good result looks like |
| --- | --- |
| SPF | One `v=spf1` record, ending in `-all`, under the 10-DNS-lookup limit |
| DMARC | `_dmarc` record with `p=reject` (or `quarantine` while rolling out), `rua=` reporting, `pct=100` |
| DKIM | A published key under a known selector, 2048-bit or stronger |
| MX | At least one MX host (two or more preferred) |

Findings are graded by severity:

| Severity | Examples |
| --- | --- |
| High | No SPF / no DMARC / no MX, multiple SPF records, `+all`, over 10 SPF lookups |
| Medium | DMARC `p=none`, SPF `~all`, no DKIM key found, weak DKIM key |
| Low | Single MX host, no `rua=` reporting, SPF close to the lookup limit |

Score starts at 100 and deducts 25 / 10 / 3 per high / medium / low
finding: 90+ is A, 75+ B, 60+ C, 40+ D, below that F.

## Install

No installation needed. Python 3.8+ only, standard library only:

```bash
git clone https://github.com/sajidhussainraza/dns-security-checker.git
cd dns-security-checker
```

## Usage

Check a domain (DKIM is probed under common selectors by default):

```bash
python3 dns_security_checker.py example.com
```

Check a specific DKIM selector:

```bash
python3 dns_security_checker.py gmail.com --selector 20161025
```

Machine-readable output:

```bash
python3 dns_security_checker.py example.com --json
```

Use it as a CI gate (fail only on high-severity findings):

```bash
python3 dns_security_checker.py example.com --fail-on high
```

Query a different resolver:

```bash
python3 dns_security_checker.py example.com --resolver 1.1.1.1
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at/above `--fail-on` |
| 1 | Findings at/above `--fail-on` were found |
| 2 | Usage error (invalid domain, DNS failure) |

## Example

```
$ python3 dns_security_checker.py gmail.com --selector 20161025
DNS security report: gmail.com
Score: 80/100  Grade: B

  SPF:   PUBLISHED
         v=spf1 redirect=_spf.google.com
  DMARC: PUBLISHED (p=none)
         v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com
  DKIM:  PUBLISHED
         selector '20161025' (key length unknown)
  MX:    alt1.gmail-smtp-in.l.google.com, alt2.gmail-smtp-in.l.google.com, ...

Findings (2):
  [MEDIUM] SPF ends in ~all (softfail) via redirect to _spf.google.com. Use -all for strict enforcement once mail flow is verified.
  [MEDIUM] DMARC policy is p=none (monitor only): spoofed mail is still delivered. Move to quarantine, then reject.
```

SPF `redirect=` targets are followed for the `-all`/`~all` check, so a
domain that redirects its SPF (like gmail.com) is judged on the record
that actually applies.

## Teaching notes

This tool pairs well with a lesson on email spoofing: run it against a
domain before and after publishing SPF/DKIM/DMARC, and watch the grade
move. Good discussion points:

- Why `p=none` is the safe starting point, and why staying on it forever
  leaves spoofed mail deliverable.
- Why SPF breaks when a domain has more than 10 DNS lookups (the
  `include:` chain), and how flattening fixes it.
- Why DKIM needs a selector, and how the selector name is the only thing
  connecting the DNS record to the signature in the mail header.

## Tests

```bash
python3 tests/run_tests.py   # 19 tests, no network access needed
```

DNS answers in the tests are faked, so the suite runs offline. (pytest
is also supported if it is installed: `python3 -m pytest tests/ -q`.)

## License

MIT
