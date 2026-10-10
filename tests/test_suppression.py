"""Tests for suppression logic (inline comments and .piiscan-ignore file)."""

from pii_scan.rules import load
from pii_scan.scanner import Config, run

_RULES_YAML = b"""
version: "1"
rules:
  - id: ssn-us
    description: SSN
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    confidence: high
    severity: critical
    category: pii
    summary: SSN detected
  - id: phone-us
    description: Phone
    pattern: '\\b\\d{3}-\\d{3}-\\d{4}\\b'
    confidence: medium
    severity: medium
    category: pii
    summary: Phone detected
"""

RULESET = load(_RULES_YAML)


def test_inline_ignore_general(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text(
        'ssn = "123-45-6789"  # piiscan:ignore\nreal_ssn = "987-65-4321"\n',
        encoding="utf-8",
    )
    result = run(Config(source=str(tmp_path), ruleset=RULESET))
    assert len(result.findings) == 2
    f1 = next(x for x in result.findings if x.line == 1)
    f2 = next(x for x in result.findings if x.line == 2)
    assert f1.suppressed is True
    assert f2.suppressed is False


def test_inline_ignore_specific_rule(tmp_path):
    f = tmp_path / "sample.py"
    f.write_text(
        'val = "123-45-6789"  # piiscan:ignore[ssn-us]\n'
        'val2 = "123-45-6789"  # piiscan:ignore[phone-us]\n',
        encoding="utf-8",
    )
    result = run(Config(source=str(tmp_path), ruleset=RULESET))
    assert len(result.findings) == 2
    f1 = next(x for x in result.findings if x.line == 1)
    f2 = next(x for x in result.findings if x.line == 2)
    assert f1.suppressed is True
    assert f2.suppressed is False


def test_piiscan_ignore_file(tmp_path):
    (tmp_path / ".piiscan-ignore").write_text(
        "# Ignore SSNs\nssn-us\n",
        encoding="utf-8",
    )
    f = tmp_path / "sample.py"
    f.write_text(
        'ssn = "123-45-6789"\nphone = "415-555-0142"\n',
        encoding="utf-8",
    )
    result = run(Config(source=str(tmp_path), ruleset=RULESET))
    assert len(result.findings) == 2
    ssn_finding = next(x for x in result.findings if x.rule_id == "pii-scan:ssn-us")
    phone_finding = next(x for x in result.findings if x.rule_id == "pii-scan:phone-us")
    assert ssn_finding.suppressed is True
    assert phone_finding.suppressed is False
