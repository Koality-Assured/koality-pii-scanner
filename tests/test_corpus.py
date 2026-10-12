"""Precision/recall regression tests over a labeled synthetic corpus.

The corpus (``testdata/corpus/labeled.jsonl``) holds one case per line:
``{"text": ..., "rules": [...]}`` where ``rules`` lists the detectors that must fire
on that line (empty = must stay silent). All values are synthetic.
"""

import json
from collections import defaultdict
from pathlib import Path

import pytest

from pii_scan.rules import default_ruleset
from pii_scan.scanner import Config, run

CORPUS = (
    Path(__file__).resolve().parent.parent / "testdata" / "corpus" / "labeled.jsonl"
)
EVALUATED = ("credit-card", "ssn-us", "email", "ipv4", "ipv6", "mac-address")
MIN_PRECISION = 0.95
MIN_RECALL = 0.95


def _load_cases() -> list[dict]:
    return [
        json.loads(line)
        for line in CORPUS.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.fixture(scope="module")
def outcomes(tmp_path_factory):
    """Scan each case as its own line and return (case, fired-rule-set) pairs."""
    cases = _load_cases()
    work = tmp_path_factory.mktemp("corpus")
    (work / "corpus.txt").write_text(
        "".join(case["text"] + "\n" for case in cases), encoding="utf-8"
    )
    result = run(Config(source=str(work), ruleset=default_ruleset()))
    fired: dict[int, set[str]] = defaultdict(set)
    for finding in result.findings:
        rule = finding.rule_id.split(":", 1)[1]
        if rule in EVALUATED:
            fired[finding.line].add(rule)
    return [(case, fired[i + 1]) for i, case in enumerate(cases)]


def test_corpus_is_labeled_and_balanced():
    cases = _load_cases()
    assert len(cases) >= 100
    for rule in EVALUATED:
        positives = sum(rule in c["rules"] for c in cases)
        assert positives >= 3, f"{rule}: needs at least 3 positive cases"
    assert sum(not c["rules"] for c in cases) >= 40, "needs plenty of negatives"
    assert all(set(c["rules"]) <= set(EVALUATED) for c in cases)


@pytest.mark.parametrize("rule", EVALUATED)
def test_precision_and_recall(outcomes, rule):
    tp = sum(rule in c["rules"] and rule in fired for c, fired in outcomes)
    fp = [
        c["text"] for c, fired in outcomes if rule in fired and rule not in c["rules"]
    ]
    fn = [
        c["text"] for c, fired in outcomes if rule in c["rules"] and rule not in fired
    ]
    precision = tp / (tp + len(fp)) if tp + len(fp) else 1.0
    recall = tp / (tp + len(fn)) if tp + len(fn) else 1.0
    assert precision >= MIN_PRECISION, f"{rule} precision {precision:.2f}; FP: {fp}"
    assert recall >= MIN_RECALL, f"{rule} recall {recall:.2f}; FN: {fn}"


def test_no_unexpected_cross_rule_hits(outcomes):
    """Stronger than the thresholds: every labeled line must match exactly."""
    mismatches = [
        (c["text"], sorted(fired), sorted(c["rules"]))
        for c, fired in outcomes
        if fired != set(c["rules"])
    ]
    assert not mismatches, mismatches
