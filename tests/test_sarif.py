"""Tests for SARIF report generation."""

import json

from pii_scan.finding import Finding
from pii_scan.rules import default_ruleset
from pii_scan.sarif import render_sarif


def test_render_sarif_structure():
    rs = default_ruleset()
    findings = [
        Finding(
            rule_id="pii-scan:ssn-us",
            source="pii-scan",
            severity="critical",
            category="pii",
            cwe=["CWE-359"],
            file="data/users.csv",
            line=5,
            summary="US Social Security Number detected",
            remediation="Remove SSN",
            redacted_match="[REDACTED]",
        ),
        Finding(
            rule_id="pii-scan:us-phone",
            source="pii-scan",
            severity="medium",
            category="pii",
            cwe=["CWE-359"],
            file="docs/readme.txt",
            line=12,
            summary="US phone number detected",
            remediation="Remove phone",
            redacted_match="[REDACTED]",
            suppressed=True,
        ),
    ]

    raw_json = render_sarif(findings, rs)
    data = json.loads(raw_json)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "koality-pii-scanner"

    # Verify results
    results = run["results"]
    assert len(results) == 2

    # Finding 1 (critical -> error)
    f1 = results[0]
    assert f1["ruleId"] == "pii-scan:ssn-us"
    assert f1["level"] == "error"
    assert (
        f1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "data/users.csv"
    )
    assert f1["locations"][0]["physicalLocation"]["region"]["startLine"] == 5
    assert "suppressions" not in f1

    # Finding 2 (medium -> warning, suppressed)
    f2 = results[1]
    assert f2["ruleId"] == "pii-scan:us-phone"
    assert f2["level"] == "warning"
    assert f2["suppressions"] == [{"kind": "inSource"}]
