#!/usr/bin/env python3
"""
agent_scan.py — standalone PII scanner for agent and automation workflows

Scans a directory or zip artifact for PII, credential, gaming-platform-id,
and advertising-identifier patterns. Designed to be invoked directly by AI
agents, Claude Code skills, pre-deploy hooks, and ad-hoc automation outside
of CI/CD pipelines.

Automatically installs pii-scan from the local repo checkout (preferred) or
from the GitHub release if not already available. No manual setup needed.

USAGE
-----
    python scripts/agent_scan.py --source PATH [OPTIONS]

    python scripts/agent_scan.py --source ./my-artifact.zip
    python scripts/agent_scan.py --source ./src --exit-code 0 --format table
    python scripts/agent_scan.py --source artifact.zip --no-redact --rules custom.yaml

OPTIONS
    --source PATH       Directory or .zip file to scan  [required]
    --format FORMAT     Output format: json (default) or table
    --exit-code N       Exit code when findings are found. 0 = never fail.
                        Default: 1 (fail when findings detected)
    --no-redact         Show actual matched values. Default: redact to [REDACTED]
    --rules PATH        Path to a custom rules YAML file. Default: embedded ruleset.
    --severity LEVEL    Only report findings at or above this severity.
                        Values: critical, high, medium, low, info. Default: info (all)

OUTPUT (JSON — stdout only)
---------------------------
All progress, warnings, and status messages go to stderr. Stdout is always
clean JSON (or a table when --format table is passed). Parse stdout directly.

JSON envelope:
    {
      "findings": [<Finding>, ...],
      "summary": {
        "total": N,
        "by_severity": {"critical": N, "high": N, "medium": N, "low": N, "info": N},
        "by_category": {"pii": N, "credentials": N, "gaming-platform-id": N, ...},
        "blocked_categories": ["credentials", "pii"]
      },
      "files_scanned": N,
      "errors": ["non-fatal warning strings"],
      "exit_code": 0 | 1 | 2,
      "source": "<path that was scanned>",
      "ruleset_version": "<version string from rules file>"
    }

Each Finding object:
    {
      "rule_id": "pii-scan:<id>",         e.g. "pii-scan:steam-id-64"
      "source": "pii-scan",
      "severity": "critical|high|medium|low|info",
      "category": "pii|credentials|financial|gaming-platform-id|advertising-identifier",
      "cwe": ["CWE-359"],                 GDPR / security classification
      "file": "relative/path/to/file",   forward-slash separated
      "line": 12,
      "summary": "short description",
      "remediation": "what to do about it",
      "redacted_match": "[REDACTED]"      or actual value when --no-redact
    }

EXIT CODES
----------
    0   No findings at or above the severity threshold
    1   One or more findings detected  (suppressed if --exit-code 0)
    2   Scanner error — bad source path, install failure, unreadable zip, etc.

BLOCKING CATEGORIES (security gate reference)
----------------------------------------------
Automated deployment pipelines and security gates commonly treat these categories as always-block:
    credentials         — API keys, tokens, private keys, OAuth secrets
    pii (CWE-359)       — SSN, credit card, phone, email in committed code
    gaming-platform-id  — only if severity is critical/high after gate policy
    advertising-identifier — high severity; ePrivacy / GDPR Recital 30

AGENT USAGE NOTES
-----------------
- Stdout is pure JSON. Stderr has human-readable progress you can surface or suppress.
- Parse the "summary.blocked_categories" list to decide whether to halt a workflow.
- "errors" contains non-fatal issues (skipped binary files, unreadable paths).
- Use --exit-code 0 when you want to inspect all findings without failing the process.
- Set --severity high to suppress low/medium noise in automated pipelines.
- This script is idempotent and read-only; it never modifies the source tree.

EXAMPLE AGENT CALL (Subprocess / Python)
----------------------------------------
    import subprocess, json
    result = subprocess.run(
        ["python", "scripts/agent_scan.py", "--source", "artifact.zip", "--exit-code", "0"],
        capture_output=True, text=True
    )
    report = json.loads(result.stdout)
    if report["summary"]["total"] > 0:
        for f in report["findings"]:
            print(f["rule_id"], f["file"], f["line"], f["summary"])
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_BLOCKING_CATEGORIES = {"credentials", "pii"}


# ── bootstrap ────────────────────────────────────────────────────────────────


def _pii_scan_available() -> bool:
    return importlib.util.find_spec("pii_scan") is not None


def _install_local(repo_root: Path) -> bool:
    r = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", str(repo_root), "-q"],
        capture_output=True,
    )
    if r.returncode == 0:
        importlib.invalidate_caches()
        return True
    _err(f"local install failed: {r.stderr.decode().strip()}")
    return False


def _install_release() -> bool:
    _err("pii-scan not found — installing from GitHub release…")
    r = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "https://github.com/Koality-Assured/koality-pii-scanner/releases/latest/download/pii_scan-latest-py3-none-any.whl",
            "-q",
        ],
        capture_output=True,
    )
    if r.returncode == 0:
        importlib.invalidate_caches()
        return True
    # fall back to pip name
    r2 = subprocess.run(
        [sys.executable, "-m", "pip", "install", "koality-pii-scanner", "-q"],
        capture_output=True,
    )
    if r2.returncode == 0:
        importlib.invalidate_caches()
        return True
    _err(f"release install failed: {r2.stderr.decode().strip()}")
    return False


def ensure_pii_scan() -> bool:
    if _pii_scan_available():
        return True
    repo_root = Path(__file__).resolve().parent.parent
    src_dir = repo_root / "src"
    if src_dir.is_dir() and str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
        if _pii_scan_available():
            return True
    if (repo_root / "pyproject.toml").exists():
        _err(f"pii-scan not installed — installing from local checkout {repo_root}")
        if _install_local(repo_root):
            return _pii_scan_available()
    return _install_release() and _pii_scan_available()


# ── helpers ───────────────────────────────────────────────────────────────────


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _severity_gte(sev: str, threshold: str) -> bool:
    try:
        return _SEVERITY_ORDER.index(sev) <= _SEVERITY_ORDER.index(threshold)
    except ValueError:
        return True


def _build_summary(findings: list, threshold: str) -> dict:
    by_sev: dict[str, int] = defaultdict(int)
    by_cat: dict[str, int] = defaultdict(int)
    for f in findings:
        by_sev[f.severity] += 1
        by_cat[f.category] += 1
    blocked = sorted(
        {f.category for f in findings if f.category in _BLOCKING_CATEGORIES}
    )
    return {
        "total": len(findings),
        "by_severity": {s: by_sev.get(s, 0) for s in _SEVERITY_ORDER},
        "by_category": dict(by_cat),
        "blocked_categories": blocked,
    }


# ── main ──────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agent_scan.py",
        description="Standalone PII scanner for agent and automation workflows.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See module docstring for full output schema and agent usage notes.",
    )
    parser.add_argument("--source", required=True, help="Directory or .zip to scan")
    parser.add_argument(
        "--format", choices=["json", "table"], default="json", dest="fmt"
    )
    parser.add_argument(
        "--exit-code",
        type=int,
        choices=[0, 1, 2],
        default=1,
        help="Exit code returned when findings are detected (default: 1)",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="Show actual matched values instead of [REDACTED]",
    )
    parser.add_argument("--rules", default=None, help="Path to custom rules YAML")
    parser.add_argument(
        "--severity",
        choices=_SEVERITY_ORDER,
        default="info",
        help="Only report findings at or above this severity (default: info = all)",
    )
    args = parser.parse_args()

    if not ensure_pii_scan():
        envelope = {
            "findings": [],
            "summary": {
                "total": 0,
                "by_severity": {},
                "by_category": {},
                "blocked_categories": [],
            },
            "files_scanned": 0,
            "errors": ["pii-scan could not be installed — see stderr for details"],
            "exit_code": 2,
            "source": args.source,
            "ruleset_version": "unavailable",
        }
        print(json.dumps(envelope, indent=2))
        return 2

    from pii_scan.rules import default_ruleset, load  # noqa: PLC0415
    from pii_scan.scanner import Config, run  # noqa: PLC0415

    # Load ruleset
    try:
        if args.rules:
            ruleset = load(Path(args.rules).read_bytes())
        else:
            ruleset = default_ruleset()
    except Exception as exc:
        _err(f"error: failed to load rules: {exc}")
        print(
            json.dumps(
                {
                    "findings": [],
                    "summary": {
                        "total": 0,
                        "by_severity": {},
                        "by_category": {},
                        "blocked_categories": [],
                    },
                    "files_scanned": 0,
                    "errors": [f"rules load failed: {exc}"],
                    "exit_code": 2,
                    "source": args.source,
                    "ruleset_version": "unavailable",
                },
                indent=2,
            )
        )
        return 2

    # Run scanner
    _err(f"scanning: {args.source}")
    try:
        result = run(
            Config(
                source=args.source,
                ruleset=ruleset,
                redact=not args.no_redact,
            )
        )
    except Exception as exc:
        _err(f"error: scanner failed: {exc}")
        print(
            json.dumps(
                {
                    "findings": [],
                    "summary": {
                        "total": 0,
                        "by_severity": {},
                        "by_category": {},
                        "blocked_categories": [],
                    },
                    "files_scanned": 0,
                    "errors": [f"scanner error: {exc}"],
                    "exit_code": 2,
                    "source": args.source,
                    "ruleset_version": ruleset.version,
                },
                indent=2,
            )
        )
        return 2

    for warning in result.errors:
        _err(f"warning: {warning}")

    # Apply severity filter
    filtered = [f for f in result.findings if _severity_gte(f.severity, args.severity)]

    summary = _build_summary(filtered, args.severity)
    _err(
        f"complete: {result.files_scanned} file(s) scanned, "
        f"{summary['total']} finding(s)"
        + (
            f" ({len(result.findings) - summary['total']} below severity threshold)"
            if len(result.findings) > summary["total"]
            else ""
        )
    )

    if args.fmt == "table":
        if not filtered:
            print("No findings.")
        else:
            print(f"  {'FILE':<45} {'LINE':>5}  {'SEV':<10}  RULE ID")
            print("  " + "-" * 80)
            for f in filtered:
                print(f"  {f.file:<45} {f.line:>5}  {f.severity:<10}  {f.rule_id}")
                print(f"    {f.summary}")
                if f.redacted_match:
                    print(f"    Match: {f.redacted_match}")
                print()
        exit_code = args.exit_code if filtered else 0
        return exit_code

    envelope = {
        "findings": [f.to_dict() for f in filtered],
        "summary": summary,
        "files_scanned": result.files_scanned,
        "errors": result.errors,
        "exit_code": args.exit_code if filtered else 0,
        "source": args.source,
        "ruleset_version": ruleset.version,
    }
    print(json.dumps(envelope, indent=2))
    return envelope["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
