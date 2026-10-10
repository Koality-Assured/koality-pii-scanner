"""Tests for Finding dataclass and is_pii_finding helper."""

import pytest

from pii_scan.finding import Finding, is_pii_finding


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        # category == "pii" alone is sufficient
        (
            {"rule_id": "pii-scan:email-address", "category": "pii", "cwe": []},
            True,
        ),
        # CWE-359 alone is sufficient even when category is not "pii"
        (
            {
                "rule_id": "pii-scan:credit-card",
                "category": "financial",
                "cwe": ["CWE-359", "CWE-312"],
            },
            True,
        ),
        # both category and CWE-359 present
        (
            {"rule_id": "pii-scan:ssn-us", "category": "pii", "cwe": ["CWE-359"]},
            True,
        ),
        # credentials category with no CWE-359 → not a PII finding
        (
            {
                "rule_id": "pii-scan:aws-access-key-id",
                "category": "credentials",
                "cwe": ["CWE-798"],
            },
            False,
        ),
        # financial category, no CWE-359
        (
            {
                "rule_id": "pii-scan:credit-card",
                "category": "financial",
                "cwe": ["CWE-312"],
            },
            False,
        ),
        # empty cwe list, non-pii category
        (
            {"rule_id": "pii-scan:bearer-token", "category": "credentials", "cwe": []},
            False,
        ),
    ],
)
def test_is_pii_finding(kwargs, expected):
    finding = Finding(**kwargs)
    assert is_pii_finding(finding) == expected


def test_to_dict_omits_empty_fields():
    f = Finding(rule_id="pii-scan:test", source="pii-scan")
    d = f.to_dict()
    # suppressed=False should be omitted (unless key is "line" or "source")
    assert "suppressed" not in d
    # source and line are always included
    assert "source" in d
    assert "line" in d


def test_to_dict_includes_populated_fields():
    f = Finding(
        rule_id="pii-scan:ssn-us",
        source="pii-scan",
        severity="critical",
        category="pii",
        cwe=["CWE-359"],
        file="data.csv",
        line=42,
        summary="SSN detected",
        remediation="Remove it",
        redacted_match="[REDACTED]",
    )
    d = f.to_dict()
    assert d["rule_id"] == "pii-scan:ssn-us"
    assert d["severity"] == "critical"
    assert d["cwe"] == ["CWE-359"]
    assert d["file"] == "data.csv"
    assert d["line"] == 42
    assert d["redacted_match"] == "[REDACTED]"


def test_finding_defaults():
    f = Finding(rule_id="pii-scan:test")
    assert f.source == "pii-scan"
    assert f.severity == "critical"
    assert f.category == "pii"
    assert f.cwe == []
    assert f.suppressed is False
