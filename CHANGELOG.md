# Changelog

All notable changes to `koality-pii-scanner` are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-10-10

### Added
- **Open-source release** under Koality Assured organization (`koality-pii-scanner`).
- **SARIF v2.1.0 Output**: `--report-format sarif` outputs standard OASIS SARIF JSON compatible with GitHub Code Scanning, VS Code, and security dashboards.
- **Suppression System**:
  - Inline comment suppression via `# piiscan:ignore`, `// piiscan:ignore`, and rule-specific comments like `# piiscan:ignore[rule-id]`.
  - Project-level suppression file `.piiscan-ignore` supporting rule IDs, file globs, and `rule:path` targets.
  - Suppressed findings recorded with `"suppressed": true` without triggering failing exit codes.
- **Single File Scanning**: Full support for directly scanning individual files via `--source <file>`.
- **Multi-Match Line Extraction**: Iterates all matches on a line so allowlisted example values adjacent to real credentials do not suppress detection of the real credential.
- **Rule Extension Filtering**: Honors `file_extensions` rule metadata to target specific file formats.
- **Directory Exclusion Defaults**: Built-in exclusion of `.git`, `node_modules`, `__pycache__`, `.pytest_cache`, `.venv`, and other build/VCS artifacts.
- Dual CLI entry points: `koality-pii-scan` and `pii-scan`.
- Added unit tests for SARIF export, suppression logic, and scanner engine enhancements (116 passing tests).

---

## [0.1.0] — 2026-06-10

### Added
- Deterministic regex-based scanner engine with zip bomb protection.
- Comprehensive default ruleset (version 2) with 59 patterns covering credentials, core PII, financial identifiers, government IDs, network/device identifiers, and gaming platform IDs.
- Value allowlist for suppressing standard documentation example keys (AWS `EXAMPLE` keys, test credit card PANs, Stripe sample keys).
- Standalone agent script `scripts/agent_scan.py` with rich summary envelope and category filtering.
- Comprehensive stored test fixtures corpus under `testdata/fixtures/` with validator script `scripts/validate_fixtures.py`.
- Redaction of matched values in reports (`--redact` / `--no-redact`).
