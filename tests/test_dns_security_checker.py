"""Tests for dns_security_checker.py. Run with: python3 -m pytest tests/ -q
(or python3 -m unittest discover -s tests -v). No network access needed:
DNS answers are faked by monkeypatching dns_query."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dns_security_checker as dsc


def _fake_dns_factory(answers):
    """answers: dict of (name, qtype) -> list of record dicts."""
    def fake_dns(name, qtype, resolver=None, port=None):
        return answers.get((name, qtype), [])
    return fake_dns


def _txt(text):
    return {"type": "TXT", "ttl": 300, "data": text}


def _mx(host, preference=10):
    return {"type": "MX", "ttl": 300,
            "data": {"preference": preference, "exchange": host}}


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

def test_spf_missing_is_high():
    findings, details = dsc.check_spf([])
    assert details["present"] is False
    assert findings[0][0] == "high"


def test_spf_good_record_is_clean():
    findings, details = dsc.check_spf(
        ["v=spf1 include:_spf.google.com -all"])
    assert details["present"] is True
    assert findings == []


def test_spf_plus_all_is_high():
    findings, _ = dsc.check_spf(["v=spf1 +all"])
    assert any(s == "high" and "+all" in m for s, m in findings)


def test_spf_too_many_lookups_is_high():
    record = "v=spf1 " + " ".join("include:spf%d.example.com" % i
                                  for i in range(11)) + " -all"
    findings, details = dsc.check_spf([record])
    assert details["dns_lookups"] == 11
    assert any(s == "high" and "11" in m for s, m in findings)


def test_spf_multiple_records_is_high():
    findings, _ = dsc.check_spf(["v=spf1 -all", "v=spf1 include:x.example -all"])
    assert any(s == "high" and "Multiple" in m for s, m in findings)


# ---------------------------------------------------------------------------
# DMARC
# ---------------------------------------------------------------------------

def test_dmarc_missing_is_high():
    findings, details = dsc.check_dmarc([])
    assert details["present"] is False
    assert findings[0][0] == "high"


def test_dmarc_reject_is_clean():
    findings, details = dsc.check_dmarc(
        ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"])
    assert details["policy"] == "reject"
    assert findings == []


def test_dmarc_none_is_medium():
    findings, details = dsc.check_dmarc(["v=DMARC1; p=none; rua=mailto:x@y.z"])
    assert details["policy"] == "none"
    assert any(s == "medium" and "p=none" in m for s, m in findings)


# ---------------------------------------------------------------------------
# DKIM / MX / grading
# ---------------------------------------------------------------------------

def test_dkim_found(monkeypatch):
    key = ("v=DKIM1; k=rsa; p=" + "QUJD" * 342)  # ~1024-byte key blob
    fake = _fake_dns_factory({
        ("default._domainkey.example.com", "TXT"): [_txt(key)],
    })
    monkeypatch.setattr(dsc, "dns_query", fake)
    findings, details = dsc.check_dkim("example.com", "8.8.8.8")
    assert details["present"] is True
    assert details["keys"][0]["selector"] == "default"


def test_dkim_missing(monkeypatch):
    monkeypatch.setattr(dsc, "dns_query", _fake_dns_factory({}))
    findings, details = dsc.check_dkim("example.com", "8.8.8.8")
    assert details["present"] is False
    assert findings[0][0] == "medium"


def test_dkim_empty_key_is_not_flagged_weak(monkeypatch):
    # Some resolvers return a DKIM record with an empty p= value; the key
    # is present but its length is unknown, so it must not be called weak.
    fake = _fake_dns_factory({
        ("default._domainkey.example.com", "TXT"): [_txt("k=rsa; p=")],
    })
    monkeypatch.setattr(dsc, "dns_query", fake)
    findings, details = dsc.check_dkim("example.com", "8.8.8.8")
    assert details["present"] is True
    assert details["keys"][0]["key_bits"] is None
    assert findings == []


def test_mx_missing_is_high():
    findings, details = dsc.check_mx([], [])
    assert details["present"] is False
    assert findings[0][0] == "high"


def test_grade_bands():
    assert dsc.grade([]) == (100, "A")
    assert dsc.grade([("low", "x")]) == (97, "A")
    assert dsc.grade([("medium", "x")]) == (90, "A")
    assert dsc.grade([("high", "x")]) == (75, "B")
    assert dsc.grade([("high", "x"), ("high", "y")]) == (50, "D")
    assert dsc.grade([("high", str(i)) for i in range(4)]) == (0, "F")


# ---------------------------------------------------------------------------
# End-to-end run_check with faked DNS
# ---------------------------------------------------------------------------

def test_run_check_clean_domain(monkeypatch):
    answers = {
        ("example.com", "TXT"): [_txt("v=spf1 include:_spf.google.com -all")],
        ("_dmarc.example.com", "TXT"): [
            _txt("v=DMARC1; p=reject; rua=mailto:dmarc@example.com")],
        ("google._domainkey.example.com", "TXT"): [
            _txt("v=DKIM1; k=rsa; p=" + "QUJD" * 684)],  # ~2048-bit key
        ("example.com", "MX"): [_mx("mail.example.com"),
                              _mx("mail2.example.com", preference=20)],
        ("example.com", "A"): [{"type": "A", "ttl": 300, "data": "93.184.216.34"}],
    }
    monkeypatch.setattr(dsc, "dns_query", _fake_dns_factory(answers))
    result = dsc.run_check("example.com", selector="google")
    assert result["grade"] == "A"
    assert result["score"] == 100
    assert result["findings"] == []


def test_run_check_broken_domain(monkeypatch):
    answers = {
        ("example.com", "TXT"): [],
        ("_dmarc.example.com", "TXT"): [],
        ("example.com", "MX"): [],
        ("example.com", "A"): [],
    }
    monkeypatch.setattr(dsc, "dns_query", _fake_dns_factory(answers))
    result = dsc.run_check("example.com")
    assert result["grade"] == "F"
    assert result["spf"]["present"] is False
    assert result["dmarc"]["present"] is False
    assert result["mx"]["present"] is False


def test_run_check_rejects_bad_domain():
    try:
        dsc.run_check("not a domain")
    except ValueError as exc:
        assert "not a valid domain" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_tag_value_separators():
    # SPF tags are space-separated; DMARC tags are semicolon-separated.
    assert dsc._tag_value("v=spf1 redirect=_spf.google.com",
                          "redirect") == "_spf.google.com"
    assert dsc._tag_value("v=DMARC1; p=none; sp=quarantine", "p") == "none"
    assert dsc._tag_value("v=DMARC1; p=none; sp=quarantine", "sp") == "quarantine"
    assert dsc._tag_value("v=DMARC1; p=none; pct=50", "pct") == "50"
    assert dsc._tag_value("v=DMARC1; p=none", "rua") is None


def test_parse_dig_output_txt_joins_segments():
    out = dsc._parse_dig_output(
        '"v=spf1 include:_spf.google.com " "-all"\n', "TXT")
    assert out[0]["data"] == "v=spf1 include:_spf.google.com -all"


def test_parse_dig_output_mx():
    out = dsc._parse_dig_output(
        "5 gmail-smtp-in.l.google.com.\n10 alt1.gmail-smtp-in.l.google.com.\n",
        "MX")
    assert out[0]["data"] == {"preference": 5,
                              "exchange": "gmail-smtp-in.l.google.com"}
    assert out[1]["data"]["preference"] == 10
