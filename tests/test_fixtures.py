"""Drive the stored fixture corpus (testdata/fixtures/) through the scanner so
detection AND false-positive guards are checked on every PR via the normal
pytest run. The validation logic is shared with scripts/validate_fixtures.py."""

import sys
from pathlib import Path

import pytest

# scripts/ is not a package — add it to the path to reuse the validator.
_SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS))

from validate_fixtures import DEFAULT_FIXTURES, collect_results  # noqa: E402

_OUTCOMES = collect_results(DEFAULT_FIXTURES)


def test_fixtures_were_collected():
    assert _OUTCOMES, "no fixtures collected from testdata/fixtures/"


@pytest.mark.parametrize("outcome", _OUTCOMES, ids=lambda o: o.name)
def test_fixture_expectation(outcome):
    assert outcome.ok, outcome.detail
