# Repository AGENTS

Repo-level agent entry point for `Koality-Assured/koality-pii-scanner` — a deterministic PII, credential, and data-sensitivity scanner that ships as a Python package, CLI (`koality-pii-scan` / `pii-scan`), and standalone agent script.

## Start Here

- Human-facing documentation and CLI reference: [`README.md`](./README.md)
- AI-assisted change provenance: [`CHANGE-HISTORY.md`](./CHANGE-HISTORY.md)
- User-facing changelog: [`CHANGELOG.md`](./CHANGELOG.md)
- Rule definitions: [`src/pii_scan/data/default.yaml`](./src/pii_scan/data/default.yaml) + [`rules/SOURCE.md`](./rules/SOURCE.md)
- Rule authoring guide: [`rules/SOURCE.md`](./rules/SOURCE.md)
- Agent-callable standalone script: [`scripts/agent_scan.py`](./scripts/agent_scan.py)
- CLI entrypoint: [`src/pii_scan/cli.py`](./src/pii_scan/cli.py)
- Core package: [`src/pii_scan/`](./src/pii_scan/)

## Ambiguity Gate

Stop and surface questions when:
- Proposed changes touch exit-code semantics or alter the core `Finding` JSON output schema.
- A proposed rule is broad enough to cause high false-positive rates on normal code or documentation.
- The distinction between suppression behavior and core rule matching is unclear.

## Session-End Completion Gates

All gates are mandatory before declaring work done:
1. **`CHANGE-HISTORY.md`** — add a top-of-list entry describing what changed, why, and what files were affected.
2. **`README.md`** — keep CLI reference, features, and examples synchronized with code changes.
3. **Tests pass** — every new rule or feature has a passing pytest case; `pytest` runs clean.
4. **Fixture validation** — if rule patterns changed, run `python scripts/validate_fixtures.py` and verify all fixtures pass.

## Area Routing

| Area | Files | Notes |
| --- | --- | --- |
| Rule definitions | `src/pii_scan/data/default.yaml`, `rules/SOURCE.md` | Primary target for pattern additions and updates |
| Finding schema | `src/pii_scan/finding.py` | Core `Finding` dataclass and dictionary serialization |
| Rule loading | `src/pii_scan/rules.py` | YAML rule parsing, compilation, and allowlist logic |
| Scanner engine | `src/pii_scan/scanner.py` | File walk, zip extraction, regex matching, redaction, and suppression |
| SARIF report | `src/pii_scan/sarif.py` | OASIS SARIF v2.1.0 JSON generation |
| CLI | `src/pii_scan/cli.py` | Click CLI, flag parsing, table and JSON output |
| Agent script | `scripts/agent_scan.py` | Standalone wrapper with rich JSON envelope |
| Test suite | `tests/` | Pytest cases for finding, rules, scanner, SARIF, and suppression |
| Test fixtures | `testdata/fixtures/` | Stored positive and negative test fixtures |

## Design Principles

### Deterministic Floor

This scanner provides an offline, deterministic, zero-network-dependency security floor. Rules are designed for high precision over noisy recall. Avoid broad regexes without word boundaries or context anchoring.

### Suppression Discipline

Suppression via `# piiscan:ignore` or `.piiscan-ignore` sets `suppressed = True` on the Finding object. Suppressed findings are recorded in output reports for auditability, but are excluded from failing process exit codes.

### Redaction

The `--redact` flag (default on) replaces matched secret values with `[REDACTED]`. The actual sensitive match should never be emitted in logs or standard reports unless explicitly requested with `--no-redact`.
