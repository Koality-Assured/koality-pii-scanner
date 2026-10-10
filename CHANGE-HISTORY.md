# Repository Change History

This file is an append-only, high-level log of material repository changes. It is intended to capture architectural decisions, schema changes, and scanner capabilities for future maintainers and agents.

---

## Entries (Newest First)

### 2026-10-10 — Koality Assured generalization, SARIF output, suppression, and scanner improvements

**Owner:** Koality Assured
**Summary:**
- Generalized the codebase into the public `koality-pii-scanner` repository under Koality Assured with zero proprietary dependencies or internal references.
- Added SARIF v2.1.0 output formatting via `--report-format sarif` for direct integration with GitHub Code Scanning and security dashboards.
- Implemented suppression system:
  - Inline comment suppression (`# piiscan:ignore`, `// piiscan:ignore`, and `# piiscan:ignore[rule-id]`).
  - Project-level `.piiscan-ignore` file support for rule IDs, file globs, and `rule:path` entries.
  - Suppressed findings recorded with `"suppressed": true` without triggering non-zero process exit codes.
- Added single-file scanning support (`--source <file>`), fixing an issue where single-file inputs were treated as empty directories.
- Implemented multi-match extraction per line: allows finding all matching tokens on a single line so allowlisted example values do not mask real secrets on the same line.
- Added automatic exclusion of default VCS and cache directories (`.git`, `node_modules`, `__pycache__`, `.pytest_cache`, `.venv`).
- Added dual console script entrypoints: `koality-pii-scan` and `pii-scan`.
- Added test suites for SARIF, suppression, and enhancements (116 tests passing).

### 2026-06-10 — Fixture corpus and allowlist validation

**Summary:**
- Added stored synthetic fixture corpus under `testdata/fixtures/` (`positive/` and `negative/` guards) and expectation manifest `expected.yaml`.
- Added fixture validation script `scripts/validate_fixtures.py` and pytest test case `tests/test_fixtures.py`.
- Added value allowlist block (`allowlist:` in `default.yaml`, ruleset version 2) for suppressing canonical documentation example keys (AWS `EXAMPLE` keys, standard test card PANs, Stripe sample secret keys).
- Added engine scan guards: minified line skip (>10,000 chars) and per-file timeout guards.

### 2026-06-03 — Comprehensive ruleset expansion

**Summary:**
- Narrowed email detection to public consumer webmail providers (`email-public-service`) to prevent false positives on corporate contact emails.
- Added rules covering financial PII (IBAN, US routing number, EIN, ITIN), government IDs (US passport, UK National Insurance, DOB), network/device identifiers (IPv4, IPv6, MAC, GPS), credentials (JWT, Stripe, SendGrid, Twilio, Firebase, npm, PyPI, GCP service account, OAuth refresh tokens), and gaming platform identifiers.
- Added synthetic fixtures and tests for all categories.
