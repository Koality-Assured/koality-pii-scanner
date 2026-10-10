"""Tests for rules loading, compilation, and matching."""

import pytest

from pii_scan.rules import Ruleset, default_ruleset, load

# Minimal inline YAML for testing
MINIMAL_YAML = b"""
version: "1"
rules:
  - id: ssn-us
    description: US Social Security Number
    pattern: '\\b(?!000|666|9\\d{2})\\d{3}[-\\s](?!00)\\d{2}[-\\s](?!0000)\\d{4}\\b'
    confidence: high
    severity: critical
    category: pii
    cwe: ["CWE-359"]
    summary: US Social Security Number detected
    remediation: Remove SSN from source files.
"""

BAD_REGEX_YAML = b"""
version: "1"
rules:
  - id: broken
    description: Rule with invalid regex
    pattern: '[unclosed bracket'
    confidence: high
    severity: critical
    category: pii
"""


class TestLoad:
    def test_load_minimal_yaml(self):
        ruleset = load(MINIMAL_YAML)
        assert isinstance(ruleset, Ruleset)
        assert ruleset.version == "1"
        assert len(ruleset.rules) == 1
        rule = ruleset.rules[0]
        assert rule.id == "ssn-us"
        assert rule.severity == "critical"
        assert rule.category == "pii"
        assert "CWE-359" in rule.cwe

    def test_load_bad_regex_raises_value_error(self):
        with pytest.raises(ValueError, match="broken"):
            load(BAD_REGEX_YAML)

    def test_load_string_input(self):
        """load() should accept str as well as bytes."""
        ruleset = load(MINIMAL_YAML.decode())
        assert len(ruleset.rules) == 1

    def test_load_empty_rules(self):
        ruleset = load(b"version: '1'\nrules: []")
        assert ruleset.rules == []

    def test_rule_defaults_applied(self):
        """Fields with defaults should be populated when omitted from YAML."""
        minimal = b"""
version: "1"
rules:
  - id: minimal-rule
    description: minimal
    pattern: '\\btest\\b'
"""
        ruleset = load(minimal)
        rule = ruleset.rules[0]
        assert rule.confidence == "medium"
        assert rule.severity == "medium"
        assert rule.category == "pii"
        assert rule.cwe == []
        assert rule.file_extensions == []


class TestDefaultRuleset:
    def test_default_ruleset_loads(self):
        ruleset = default_ruleset()
        assert isinstance(ruleset, Ruleset)
        assert len(ruleset.rules) >= 5

    def test_default_ruleset_has_expected_ids(self):
        ruleset = default_ruleset()
        ids = {r.id for r in ruleset.rules}
        assert "ssn-us" in ids
        assert "credit-card" in ids
        assert "aws-access-key-id" in ids
        assert "email-public-service" in ids
        assert "pem-private-key" in ids

    def test_default_ruleset_all_rules_compiled(self):
        """Every rule in the default ruleset should compile without error."""
        ruleset = default_ruleset()
        for rule in ruleset.rules:
            # _compiled is set during load(); just ensure match() works
            assert rule._compiled is not None


class TestRuleMatch:
    def setup_method(self):
        self.ruleset = load(MINIMAL_YAML)
        self.ssn_rule = self.ruleset.rules[0]

    def test_match_returns_matched_string(self):
        line = "Customer SSN: 123-45-6789 on file."
        matched = self.ssn_rule.match(line)
        assert matched is not None
        assert "123-45-6789" in matched

    def test_match_returns_none_for_non_match(self):
        line = "No sensitive data here."
        assert self.ssn_rule.match(line) is None

    def test_match_returns_none_for_empty_line(self):
        assert self.ssn_rule.match("") is None

    def test_match_compiles_on_demand(self):
        """Rule with _compiled=None should auto-compile on first match call."""
        ruleset = load(MINIMAL_YAML)
        rule = ruleset.rules[0]
        rule._compiled = None  # force re-compile on demand
        matched = rule.match("ssn: 234-56-7890")
        assert matched is not None


class TestAllowlist:
    """Allowlist parsing and suppression behavior."""

    # Rule pattern deliberately avoids word-boundary escapes to keep the inline
    # YAML free of backslash escaping; the allowlist behavior is what we test.
    ALLOWLIST_YAML = b"""
version: "2"
allowlist:
  literals:
    - "AKIAIOSFODNN7EXAMPLE"
    - "4242424242424242"
  patterns:
    - '^(?:AKIA|ASIA)[0-9A-Z]+EXAMPLE$'
rules:
  - id: aws-key
    description: AWS key
    pattern: '(AKIA|ASIA)[0-9A-Z]{16}'
    confidence: high
    severity: critical
    category: credentials
"""

    def test_allowlist_parsed(self):
        rs = load(self.ALLOWLIST_YAML)
        assert "AKIAIOSFODNN7EXAMPLE" in rs.allowlist.literals
        assert len(rs.allowlist.patterns) == 1

    def test_literal_suppressed(self):
        rs = load(self.ALLOWLIST_YAML)
        assert rs.allowlist.suppresses("AKIAIOSFODNN7EXAMPLE") is True
        assert rs.allowlist.suppresses("4242424242424242") is True

    def test_pattern_suppressed(self):
        rs = load(self.ALLOWLIST_YAML)
        assert rs.allowlist.suppresses("AKIAABCDEFGH1234EXAMPLE") is True

    def test_real_value_not_suppressed(self):
        rs = load(self.ALLOWLIST_YAML)
        assert rs.allowlist.suppresses("AKIA1234567890ABCDEF") is False

    def test_missing_allowlist_is_empty(self):
        rs = load(MINIMAL_YAML)
        assert rs.allowlist.literals == frozenset()
        assert rs.allowlist.patterns == []
        assert rs.allowlist.suppresses("anything") is False

    def test_bad_allowlist_pattern_raises(self):
        bad = b"""
version: "2"
allowlist:
  patterns:
    - '[unclosed'
rules: []
"""
        with pytest.raises(ValueError):
            load(bad)

    def test_default_ruleset_has_allowlist(self):
        rs = default_ruleset()
        assert "AKIAIOSFODNN7EXAMPLE" in rs.allowlist.literals
        assert rs.allowlist.suppresses("AKIAIOSFODNN7EXAMPLE") is True
