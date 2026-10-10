#!/usr/bin/env python3
"""
Validate the PII scanner against the stored fixture corpus.

Two kinds of fixtures live under ``testdata/fixtures/``:

* ``positive/`` — files that MUST produce findings. ``expected.yaml`` lists, per
  file, the ``rule_id``s that must appear (extra incidental matches are allowed).
* ``negative/`` — false-positive guards that MUST produce ZERO findings
  (allowlisted example tokens, internal/example emails, look-alike values).

The corpus is scanned with the embedded default ruleset (allowlist included), so
the run reflects exactly what the engine does in production. All fixture values
are SYNTHETIC — no real credentials or personal data.

Usage:
    python scripts/validate_fixtures.py [--fixtures testdata/fixtures]

Exit code 0 when every expectation holds, 1 otherwise (with a per-fixture report).
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import yaml

# Allow running from a source checkout without an editable install.
_SRC = Path(__file__).resolve().parent.parent / "src"
if _SRC.is_dir() and str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from pii_scan.rules import default_ruleset  # noqa: E402
from pii_scan.scanner import Config, run  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FIXTURES = REPO_ROOT / "testdata" / "fixtures"


@dataclass
class Outcome:
    name: str
    ok: bool
    detail: str


def _scan_dir_by_file(directory: Path) -> dict[str, set[str]]:
    """Scan a directory and return {relative_file: {rule_id, ...}}."""
    found: dict[str, set[str]] = defaultdict(set)
    if not directory.is_dir():
        return found
    result = run(Config(source=str(directory), ruleset=default_ruleset(), redact=True))
    for f in result.findings:
        found[f.file].add(f.rule_id)
    return found


def collect_results(fixtures_dir: Path) -> list[Outcome]:
    """Run both fixture sets and return one Outcome per checked fixture."""
    manifest = yaml.safe_load(
        (fixtures_dir / "expected.yaml").read_text(encoding="utf-8")
    )
    outcomes: list[Outcome] = []

    # ── Positive fixtures: expected rule_ids must all be present ──────────────
    pos_found = _scan_dir_by_file(fixtures_dir / "positive")
    for filename, expected_ids in sorted((manifest.get("positive") or {}).items()):
        expected = set(expected_ids)
        found = pos_found.get(filename, set())
        missing = expected - found
        outcomes.append(
            Outcome(
                name=f"positive/{filename}",
                ok=not missing,
                detail=(
                    "ok — " + ", ".join(sorted(expected))
                    if not missing
                    else f"MISSING {sorted(missing)} (found {sorted(found) or 'nothing'})"
                ),
            )
        )

    # ── Negative fixtures: must produce zero findings ─────────────────────────
    neg_found = _scan_dir_by_file(fixtures_dir / "negative")
    for filename in sorted(manifest.get("negative") or []):
        hits = neg_found.get(filename, set())
        outcomes.append(
            Outcome(
                name=f"negative/{filename}",
                ok=not hits,
                detail="ok — no findings"
                if not hits
                else f"UNEXPECTED findings {sorted(hits)}",
            )
        )

    return outcomes


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--fixtures",
        default=str(DEFAULT_FIXTURES),
        help="Path to the fixtures directory",
    )
    args = ap.parse_args()

    outcomes = collect_results(Path(args.fixtures))
    if not outcomes:
        print("No fixtures found — nothing to validate.")
        return 1

    failures = [o for o in outcomes if not o.ok]
    for o in outcomes:
        print(f"  {'PASS' if o.ok else 'FAIL'}  {o.name}: {o.detail}")
    print(f"\n{len(outcomes) - len(failures)}/{len(outcomes)} fixtures passed.")
    if failures:
        print(f"FAILED: {len(failures)} fixture expectation(s) not met.")
        return 1
    print("All fixture expectations met.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
