# CLAUDE.md — koality-pii-scanner

This file is the agent entry point for this repository.

## Step 1: Read AGENTS.md first

[`AGENTS.md`](./AGENTS.md) is the primary agent entry point. It defines:
- Ambiguity gate and session-end completion gates
- Area routing and file ownership
- Design principles and suppression discipline

## Step 2: Language and Scripting

**Python is the primary language for everything in this repository:**
- Scanner core (`src/pii_scan/`), CLI, rule parsing, tests — all Python
- Scripts and automation (`scripts/`) — all Python
- Use `pytest` for testing and `ruff` for formatting/linting

## Common Commands

```bash
# Run test suite
pytest

# Validate test fixtures
python scripts/validate_fixtures.py

# Format and lint
ruff format src/ tests/
ruff check src/ tests/

# Test CLI
pii-scan detect --source testdata/clean/index.html --report-format json
```
