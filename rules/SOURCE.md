# PII Scanner Rules — Source Documentation

The authoritative rule file is at `src/pii_scan/data/default.yaml`. It is embedded into the Python package at build time via `importlib.resources`.

## Rule format

Each rule in `default.yaml` has:
- `id` — unique rule identifier (used as suffix in `rule_id` field: `pii-scan:<id>`)
- `description` — human-readable name
- `pattern` — Python `re` regex (PCRE — lookaheads and lookbehinds are supported)
- `confidence` — `high` / `medium` / `low`
- `severity` — `critical` / `high` / `medium` / `low` / `info`
- `category` — see categories below
- `cwe` — list of CWE IDs
- `summary` — short finding description
- `remediation` — action the developer should take
- `file_extensions` — (optional) list of file extensions to limit which files are scanned

## Categories

| Category | Description | Default Policy Behavior |
|---|---|---|
| `pii` | Directly identifiable personal data (SSN, phone, email) | Blocks via PII security policy |
| `financial` | Payment card numbers, account numbers, tax IDs | Blocks via severity threshold |
| `credentials` | API keys, tokens, private keys, OAuth secrets | Blocks via Secret / Credential policy |
| `gaming-platform-id` | Platform account identifiers (Steam, PSN, Xbox, Epic, Nintendo, Riot, etc.) | Warns; blocks via severity threshold if `high`/`critical` |
| `advertising-identifier` | IDFA, GAID — mobile advertising IDs | Warns at `high` severity |
| `gaming-personalization` | In-game balances, MMR, hardware fingerprints | Advisory or security policy warning |

## How to update rules

1. Edit `src/pii_scan/data/default.yaml`
2. Add a test in `tests/test_scanner.py` or `tests/test_rules.py` exercising the pattern
3. Run `pytest` and verify all tests pass
4. Update the rule history table below with date, change, and rationale
5. Bump `VERSION` and update `CHANGELOG.md` if releasing

## Regex guidelines

Python `re` supports the full PCRE feature set including lookaheads (`(?=...)`, `(?!...)`), lookbehinds (`(?<=...)`, `(?<!...)`), and backreferences. Use `\b` for word boundaries. Use `(?i)` for case-insensitive matching.

**False positive strategy:**

- **High-confidence prefix-anchored patterns** (e.g., `7656119\d{10}` for SteamID64, `STEAM_` prefix, `SW-\d{4}` for Switch Friend Code) run without context requirements — the prefix is distinctive enough.
- **Generic numeric or hex patterns** (e.g., 32-character hex strings, 15-digit numbers) are always context-anchored — the pattern must include a variable name or keyword prefix from the same line to avoid false positives.
- Test new patterns against representative false-positive inputs (MD5 hashes, UUID v4 values, phone numbers, version strings) before adding with `confidence: high`.

## Value allowlist (false-positive suppression)

`default.yaml` carries an `allowlist:` block (ruleset `version: "2"`+). A rule's
**matched value** is suppressed (no finding emitted) when it:

- equals an entry in `allowlist.literals` (exact match), or
- is matched by an entry in `allowlist.patterns` (regex `search`).

Suppression is evaluated per matched value — never the whole line — so a real
secret on the same line as an example is still reported.

Use it for **known-safe** values that are documentation examples, vendor
canonical placeholders, or standard payment-network sandbox fixtures. Current
contents:

- AWS canonical example keys: `AKIAIOSFODNN7EXAMPLE` (and any AWS key value ending in `EXAMPLE`, via pattern `^(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]+EXAMPLE$`)
- Standard test card numbers (Visa/MC/Amex/Discover/Diners/JCB sandbox PANs, contiguous form)
- Stripe documentation sample secret key

**Do not** add real values, internal identifiers, or whole rule categories to the
allowlist — for "this rule is too noisy," tighten the rule's regex instead. The
allowlist is for individual known-fake tokens, not for disabling detection.

## Corporate and internal email handling

The `email-public-service` rule is intentionally configured to only match known public consumer webmail providers (Gmail, Yahoo, Hotmail, Outlook, iCloud, ProtonMail, etc.). Corporate email addresses and custom domain emails are excluded from this rule by design, which avoids flagging legitimate business contact addresses in documentation, codeowners, and configuration files.

## Suppression Mechanisms

The scanner supports two suppression mechanisms:
1. **Inline comment suppression**:
   Developers can append a comment to any line to suppress findings:
   - `# piiscan:ignore` or `// piiscan:ignore` (suppresses all findings on that line)
   - `# piiscan:ignore[ssn-us]` (suppresses only `ssn-us` on that line)
2. **`.piiscan-ignore` file**:
   A `.piiscan-ignore` file at the root of the project can specify rule IDs, file globs, or `rule:path` targets to suppress. Suppressed findings are recorded in output with `"suppressed": true` and excluded from failure exit codes.

---

## Rule history

| Date | Change | Rationale |
|---|---|---|
| 2026-06-02 | Initial ruleset: ssn-us, credit-card, us-phone, email-address, aws-access-key-id, bearer-token, github-token, slack-token, pem-private-key | Bootstrap — primary PII and credential categories for deterministic pre-deploy security gate |
| 2026-06-03 | email-address → email-public-service (only public consumer providers); 35 new rules: financial PII (iban, us-routing-number, us-ein, us-itin), government IDs (us-passport-number, uk-national-insurance, date-of-birth), network/device (ipv4-user-context, ipv6-user-context, mac-address-context, gps-latitude, gps-longitude), credentials (jwt-token, stripe-live-api-key, stripe-restricted-key, stripe-webhook-secret, sendgrid-api-key, twilio-account-sid, firebase-api-key, npm-auth-token, pypi-api-token, gcp-service-account-key, oauth-refresh-token), gaming-personalization (hwid-context, session-token-context, matchmaking-rating, in-game-currency-balance), GDPR Art. 9 special categories (health-data-context, biometric-data-context, gender-identity-context, racial-ethnic-origin-context, political-religious-belief-context) | Email rule narrowed to public consumer providers to prevent false positives on corporate emails. GDPR Art. 9 special categories require explicit consent. Credential rules cover common SaaS and cloud providers. |
| 2026-06-02 | Gaming platform identifiers: steam-id-64, steam-id-legacy, steam-id3, nintendo-switch-friend-code, psn-npwr-trophy-id, xbox-xuid-url, xbox-xuid-context, epic-account-id-context, epic-oauth-credential-pair, psn-online-id-context, nintendo-account-id-context, apple-game-center-player-id, apple-game-center-team-id, riot-id-context, battletag-context, discord-snowflake-context; advertising identifiers: advertising-id-idfa, advertising-id-gaid | GDPR Art. 4(1) / Recital 30: all gaming account identifiers are online identifiers = personal data. Sources: EDPB Guidelines, ICO Children's Code, CNIL enforcement. |
| 2026-06-10 | Added `allowlist:` block (ruleset version "2") — value suppression for AWS canonical example keys (`AKIAIOSFODNN7EXAMPLE` + `EXAMPLE`-suffix pattern), standard payment-network test PANs, Stripe doc sample key. Ported engine guards: minified-line skip (>10k chars) + per-file 15s timeout. | Evaluation found PII false positives dominated by doc example tokens, vendored SDK example data, and generated schema snapshots. Value allowlist suppresses known-fake tokens without weakening real detection. |
| 2026-10-10 | Koality Assured generalization (version 0.2.0): SARIF v2.1.0 report generation, `.piiscan-ignore` file and inline comment suppression, single-file scanning support, multi-match per line extraction, and directory exclusion defaults. | Open-source release under Koality-Assured organization. |
