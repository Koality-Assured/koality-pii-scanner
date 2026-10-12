"""Tests for the scanner.run() function."""

import zipfile
from pathlib import Path

from pii_scan.rules import load
from pii_scan.scanner import Config, run

# Self-contained single-rule ruleset for all scanner tests
_SSN_YAML = b"""
version: "1"
rules:
  - id: ssn-simple
    description: Simple SSN pattern for tests
    pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b'
    confidence: high
    severity: critical
    category: pii
    cwe: ["CWE-359"]
    summary: SSN detected
    remediation: Remove it.
"""

SSN_RULESET = load(_SSN_YAML)


def _make_config(source: str, redact: bool = True) -> Config:
    return Config(source=source, ruleset=SSN_RULESET, redact=redact)


class TestCleanDirectory:
    def test_no_findings_in_empty_dir(self, tmp_path):
        result = run(_make_config(str(tmp_path)))
        assert result.findings == []
        assert result.errors == []
        assert result.files_scanned == 0

    def test_no_findings_clean_text_file(self, tmp_path):
        (tmp_path / "clean.txt").write_text(
            "Hello world, no PII here.\n", encoding="utf-8"
        )
        result = run(_make_config(str(tmp_path)))
        assert result.findings == []
        assert result.files_scanned == 1


class TestDirtyDirectory:
    def test_ssn_in_csv_produces_finding(self, tmp_path):
        (tmp_path / "data.csv").write_text(
            "name,ssn\nAlice,123-45-6789\n", encoding="utf-8"
        )
        result = run(_make_config(str(tmp_path)))
        assert len(result.findings) >= 1
        assert result.findings[0].rule_id == "pii-scan:ssn-simple"

    def test_finding_file_path_uses_forward_slash(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "data.csv").write_text("ssn: 234-56-7890\n", encoding="utf-8")
        result = run(_make_config(str(tmp_path)))
        assert result.findings[0].file == "sub/data.csv"

    def test_finding_line_number_is_correct(self, tmp_path):
        content = "no ssn here\nno ssn here\nssn: 345-67-8901\n"
        (tmp_path / "file.txt").write_text(content, encoding="utf-8")
        result = run(_make_config(str(tmp_path)))
        assert result.findings[0].line == 3

    def test_multiple_findings_in_one_file(self, tmp_path):
        content = "ssn1: 111-22-3333\nssn2: 444-55-6666\n"
        (tmp_path / "multi.txt").write_text(content, encoding="utf-8")
        result = run(_make_config(str(tmp_path)))
        assert len(result.findings) == 2

    def test_binary_file_skipped(self, tmp_path):
        (tmp_path / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        result = run(_make_config(str(tmp_path)))
        assert result.findings == []
        assert result.files_scanned == 0


class TestRedaction:
    def test_redact_true_replaces_match(self, tmp_path):
        (tmp_path / "data.txt").write_text("ssn: 123-45-6789\n", encoding="utf-8")
        result = run(_make_config(str(tmp_path), redact=True))
        assert result.findings[0].redacted_match == "[REDACTED]"

    def test_redact_false_preserves_actual_value(self, tmp_path):
        (tmp_path / "data.txt").write_text("ssn: 123-45-6789\n", encoding="utf-8")
        result = run(_make_config(str(tmp_path), redact=False))
        assert result.findings[0].redacted_match == "123-45-6789"

    def test_redact_false_does_not_contain_redacted_string(self, tmp_path):
        (tmp_path / "data.txt").write_text("ssn: 234-56-7890\n", encoding="utf-8")
        result = run(_make_config(str(tmp_path), redact=False))
        assert result.findings[0].redacted_match != "[REDACTED]"


class TestZipInput:
    def _make_zip(self, files: dict[str, str], dest: Path) -> Path:
        """Create a zip file at dest containing the given filename->content mapping."""
        zip_path = dest / "test.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return zip_path

    def test_zip_with_dirty_file_produces_finding(self, tmp_path):
        zip_path = self._make_zip({"data.csv": "name,ssn\nBob,456-78-9012\n"}, tmp_path)
        result = run(_make_config(str(zip_path)))
        assert len(result.findings) >= 1
        assert result.findings[0].rule_id == "pii-scan:ssn-simple"

    def test_zip_with_clean_file_no_findings(self, tmp_path):
        zip_path = self._make_zip({"clean.txt": "nothing sensitive\n"}, tmp_path)
        result = run(_make_config(str(zip_path)))
        assert result.findings == []

    def test_zip_redact_true(self, tmp_path):
        zip_path = self._make_zip({"data.txt": "ssn: 567-89-0123\n"}, tmp_path)
        result = run(_make_config(str(zip_path), redact=True))
        assert result.findings[0].redacted_match == "[REDACTED]"

    def test_zip_redact_false(self, tmp_path):
        zip_path = self._make_zip({"data.txt": "ssn: 567-89-0123\n"}, tmp_path)
        result = run(_make_config(str(zip_path), redact=False))
        assert result.findings[0].redacted_match == "567-89-0123"

    def test_bad_zip_returns_error(self, tmp_path):
        bad_zip = tmp_path / "bad.zip"
        bad_zip.write_bytes(b"this is not a zip file")
        result = run(_make_config(str(bad_zip)))
        assert result.errors
        assert "bad zip" in result.errors[0].lower()

    def test_zip_multiple_files(self, tmp_path):
        zip_path = self._make_zip(
            {
                "clean.txt": "no pii here\n",
                "dirty.csv": "ssn: 678-90-1234\n",
            },
            tmp_path,
        )
        result = run(_make_config(str(zip_path)))
        assert result.files_scanned == 2
        assert len(result.findings) == 1


class TestGamingPlatformIds:
    """Tests for gaming-specific PII rules using the embedded default ruleset."""

    def _run_on(self, tmp_path, content: str, filename: str = "test.js"):
        from pii_scan.rules import default_ruleset

        (tmp_path / filename).write_text(content, encoding="utf-8")
        cfg = Config(source=str(tmp_path), ruleset=default_ruleset(), redact=True)
        return run(cfg)

    def test_steam_id64_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'const steamId = "76561198012345678";\n')
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:steam-id-64" in ids

    def test_steam_id_legacy_detected(self, tmp_path):
        result = self._run_on(
            tmp_path, "player_id: STEAM_0:1:123456789\n", "config.yaml"
        )
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:steam-id-legacy" in ids

    def test_steam_id3_detected(self, tmp_path):
        result = self._run_on(tmp_path, "id: [U:1:123456789]\n", "config.yaml")
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:steam-id3" in ids

    def test_nintendo_switch_friend_code_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'friendCode = "SW-1234-5678-9012";\n')
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:nintendo-switch-friend-code" in ids

    def test_xbox_xuid_url_notation_detected(self, tmp_path):
        result = self._run_on(
            tmp_path, 'const url = "/users/xuid(2533274790412952)/profile";\n'
        )
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:xbox-xuid-url" in ids

    def test_xbox_xuid_context_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'xuid = "2533274790412952"\n', "config.py")
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:xbox-xuid-context" in ids

    def test_epic_oauth_credential_pair_detected(self, tmp_path):
        result = self._run_on(
            tmp_path,
            'secret = "3446cd72694c4a4485d81b77adbb2141:9209d4a5e25a457fb9b07489d313b41a"\n',
        )
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:epic-oauth-credential-pair" in ids

    def test_epic_oauth_pair_severity_is_critical(self, tmp_path):
        result = self._run_on(
            tmp_path,
            'credentials = "3446cd72694c4a4485d81b77adbb2141:9209d4a5e25a457fb9b07489d313b41a"\n',
        )
        epic = next(
            f
            for f in result.findings
            if f.rule_id == "pii-scan:epic-oauth-credential-pair"
        )
        assert epic.severity == "critical"

    def test_psn_npwr_trophy_id_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'trophy_id = "NPWR12345_00"\n', "config.py")
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:psn-npwr-trophy-id" in ids

    def test_apple_game_center_legacy_id_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'playerID = "G:123456789"\n')
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:apple-game-center-player-id" in ids

    def test_apple_game_center_team_id_detected(self, tmp_path):
        result = self._run_on(
            tmp_path, 'teamID = "T:_3446cd72694c4a4485d81b77adbb2141"\n'
        )
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:apple-game-center-team-id" in ids

    def test_discord_snowflake_context_detected(self, tmp_path):
        result = self._run_on(
            tmp_path, 'discord_user_id = "123456789012345678"\n', "config.py"
        )
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:discord-snowflake-context" in ids

    def test_advertising_id_idfa_detected(self, tmp_path):
        result = self._run_on(
            tmp_path,
            'idfa = "6D92078A-8246-4674-8B58-1C41C25E8F0A"\n',
        )
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:advertising-id-idfa" in ids

    def test_advertising_id_gaid_detected(self, tmp_path):
        result = self._run_on(
            tmp_path,
            'gaid = "38400000-8cf0-11bd-b23e-10b96e40000d"\n',
        )
        ids = [f.rule_id for f in result.findings]
        assert "pii-scan:advertising-id-gaid" in ids

    def test_advertising_id_severity_is_high_not_critical(self, tmp_path):
        result = self._run_on(
            tmp_path,
            'idfa = "6D92078A-8246-4674-8B58-1C41C25E8F0A"\n',
        )
        idfa = next(
            f for f in result.findings if f.rule_id == "pii-scan:advertising-id-idfa"
        )
        assert idfa.severity == "high"

    def test_gaming_id_category_is_gaming_platform_id(self, tmp_path):
        result = self._run_on(tmp_path, 'const steamId = "76561198012345678";\n')
        steam = next(f for f in result.findings if f.rule_id == "pii-scan:steam-id-64")
        assert steam.category == "gaming-platform-id"

    def test_clean_file_no_gaming_findings(self, tmp_path):
        result = self._run_on(tmp_path, "const greeting = 'hello world';\n")
        gaming_findings = [
            f for f in result.findings if f.category == "gaming-platform-id"
        ]
        assert gaming_findings == []


class TestResultStructure:
    def test_result_has_files_scanned_count(self, tmp_path):
        (tmp_path / "a.txt").write_text("clean\n", encoding="utf-8")
        (tmp_path / "b.txt").write_text("also clean\n", encoding="utf-8")
        result = run(_make_config(str(tmp_path)))
        assert result.files_scanned == 2

    def test_finding_fields_populated(self, tmp_path):
        (tmp_path / "data.txt").write_text("ssn: 123-45-6789\n", encoding="utf-8")
        result = run(_make_config(str(tmp_path)))
        f = result.findings[0]
        assert f.file == "data.txt"
        assert f.line == 1
        assert f.source == "pii-scan"
        assert f.severity == "critical"
        assert f.category == "pii"
        assert "CWE-359" in f.cwe

    def test_to_dict_is_json_serializable(self, tmp_path):
        import json

        (tmp_path / "data.txt").write_text("ssn: 123-45-6789\n", encoding="utf-8")
        result = run(_make_config(str(tmp_path)))
        # Should not raise
        serialized = json.dumps([f.to_dict() for f in result.findings])
        data = json.loads(serialized)
        assert len(data) == 1


class TestExpandedRuleset:
    """Tests for the expanded PII ruleset using the embedded default ruleset."""

    def _run_on(self, tmp_path, content: str, filename: str = "test.py"):
        from pii_scan.rules import default_ruleset

        (tmp_path / filename).write_text(content, encoding="utf-8")
        cfg = Config(source=str(tmp_path), ruleset=default_ruleset(), redact=True)
        return run(cfg)

    def _ids(self, result):
        return [f.rule_id for f in result.findings]

    # Email
    def test_gmail_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'contact = "user@gmail.com"\n')
        assert "pii-scan:email-public-service" in self._ids(result)

    def test_internal_corporate_email_detected_by_general_rule(self, tmp_path):
        result = self._run_on(tmp_path, 'owner = "dev@koalityassured.com"\n')
        ids = self._ids(result)
        assert "pii-scan:email" in ids
        assert "pii-scan:email-public-service" not in ids

    def test_internal_custom_domain_email_not_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'admin = "admin@internal.example.org"\n')
        assert not any("email" in rid for rid in self._ids(result))

    # Financial
    def test_iban_detected(self, tmp_path):
        result = self._run_on(
            tmp_path, 'iban = "GB29NWBK60161331926819"\n', "config.py"
        )
        assert "pii-scan:iban" in self._ids(result)

    def test_us_routing_number_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'routing_number = "021000021"\n', "config.py")
        assert "pii-scan:us-routing-number" in self._ids(result)

    def test_us_ein_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'ein = "12-3456789"\n', "config.py")
        assert "pii-scan:us-ein" in self._ids(result)

    # Government IDs
    def test_uk_ni_detected(self, tmp_path):
        result = self._run_on(tmp_path, "ni_number = AB123456C\n", "config.py")
        assert "pii-scan:uk-national-insurance" in self._ids(result)

    def test_date_of_birth_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'dob = "1990-05-15"\n', "config.py")
        assert "pii-scan:date-of-birth" in self._ids(result)

    def test_us_passport_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'passport_number = "A12345678"\n', "config.py")
        assert "pii-scan:us-passport-number" in self._ids(result)

    # Network/device
    def test_user_ip_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'user_ip = "192.168.1.100"\n', "config.py")
        assert "pii-scan:ipv4-user-context" in self._ids(result)

    def test_mac_address_detected(self, tmp_path):
        result = self._run_on(
            tmp_path, 'mac_address = "AA:BB:CC:DD:EE:FF"\n', "config.py"
        )
        assert "pii-scan:mac-address-context" in self._ids(result)

    def test_gps_latitude_detected(self, tmp_path):
        result = self._run_on(tmp_path, "lat = 37.7749\n", "config.py")
        assert "pii-scan:gps-latitude" in self._ids(result)

    def test_gps_longitude_detected(self, tmp_path):
        result = self._run_on(tmp_path, "lng = -122.4194\n", "config.py")
        assert "pii-scan:gps-longitude" in self._ids(result)

    # Credentials
    def test_jwt_detected(self, tmp_path):
        result = self._run_on(
            tmp_path,
            'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n',
        )
        assert "pii-scan:jwt-token" in self._ids(result)

    def test_stripe_live_key_detected(self, tmp_path):
        # Constructed at runtime — not a literal credential; avoids push protection
        key = "sk" + "_live_" + "abcdefghijklmnopqrstuvwx"
        result = self._run_on(tmp_path, f'key = "{key}"\n')
        assert "pii-scan:stripe-live-api-key" in self._ids(result)

    def test_stripe_webhook_secret_detected(self, tmp_path):
        secret = "whsec" + "_abcdefghijklmnopqrstuvwxyz123456"
        result = self._run_on(tmp_path, f'secret = "{secret}"\n')
        assert "pii-scan:stripe-webhook-secret" in self._ids(result)

    def test_firebase_key_detected(self, tmp_path):
        key = "AIza" + "SyD-abcdefghijklmnopqrstuvwxyz12345"
        result = self._run_on(tmp_path, f'apiKey = "{key}"\n')
        assert "pii-scan:firebase-api-key" in self._ids(result)

    def test_npm_token_detected(self, tmp_path):
        token = "npm" + "_abcdefghijklmnopqrstuvwxyz12345678"
        result = self._run_on(tmp_path, f'NPM_TOKEN = "{token}"\n')
        assert "pii-scan:npm-auth-token" in self._ids(result)

    def test_gcp_service_account_detected(self, tmp_path):
        result = self._run_on(
            tmp_path,
            '{"type": "service_account", "project_id": "my-project"}\n',
            "creds.json",
        )
        assert "pii-scan:gcp-service-account-key" in self._ids(result)

    # Gaming personalization
    def test_hwid_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'hwid = "A1B2C3D4E5F6G7H8"\n', "config.py")
        assert "pii-scan:hwid-context" in self._ids(result)

    def test_session_token_detected(self, tmp_path):
        result = self._run_on(
            tmp_path, 'session_id = "abcdef1234567890abcdef1234567890"\n', "config.py"
        )
        assert "pii-scan:session-token-context" in self._ids(result)

    def test_mmr_detected(self, tmp_path):
        result = self._run_on(tmp_path, "mmr = 2450\n", "config.py")
        assert "pii-scan:matchmaking-rating" in self._ids(result)

    def test_mmr_severity_is_low(self, tmp_path):
        result = self._run_on(tmp_path, "mmr = 2450\n", "config.py")
        f = next(
            x for x in result.findings if x.rule_id == "pii-scan:matchmaking-rating"
        )
        assert f.severity == "low"

    # GDPR Art. 9
    def test_health_data_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'diagnosis = "Type 2 diabetes"\n', "config.py")
        assert "pii-scan:health-data-context" in self._ids(result)

    def test_biometric_detected(self, tmp_path):
        result = self._run_on(tmp_path, 'fingerprint_hash = "abc123"\n', "config.py")
        assert "pii-scan:biometric-data-context" in self._ids(result)

    def test_art9_severity_is_critical(self, tmp_path):
        result = self._run_on(tmp_path, 'diagnosis = "hypertension"\n', "config.py")
        f = next(
            x for x in result.findings if x.rule_id == "pii-scan:health-data-context"
        )
        assert f.severity == "critical"


class TestAllowlist:
    """Known-safe values (doc examples, vendor placeholders, test card numbers)
    are suppressed; real-looking values are still detected."""

    def _run_on(self, tmp_path, content: str, filename: str = "test.py"):
        from pii_scan.rules import default_ruleset

        (tmp_path / filename).write_text(content, encoding="utf-8")
        cfg = Config(source=str(tmp_path), ruleset=default_ruleset(), redact=True)
        return run(cfg)

    def _ids(self, result):
        return [f.rule_id for f in result.findings]

    def test_aws_example_key_suppressed(self, tmp_path):
        result = self._run_on(tmp_path, "key = AKIAIOSFODNN7EXAMPLE\n", "config.py")
        assert "pii-scan:aws-access-key-id" not in self._ids(result)

    def test_aws_example_pattern_suppressed(self, tmp_path):
        # Any AWS key value ending in EXAMPLE matches the allowlist pattern
        result = self._run_on(tmp_path, "key = AKIAABCDEFGH12EXAMPLE\n", "config.py")
        assert "pii-scan:aws-access-key-id" not in self._ids(result)

    def test_real_aws_key_still_detected(self, tmp_path):
        result = self._run_on(tmp_path, "key = AKIA1234567890ABCDEF\n", "config.py")
        assert "pii-scan:aws-access-key-id" in self._ids(result)

    def test_test_credit_card_suppressed(self, tmp_path):
        result = self._run_on(tmp_path, "card = 4242424242424242\n", "config.py")
        assert "pii-scan:credit-card" not in self._ids(result)

    def test_amex_test_card_suppressed(self, tmp_path):
        result = self._run_on(tmp_path, "card = 378282246310005\n", "config.py")
        assert "pii-scan:credit-card" not in self._ids(result)

    def test_real_credit_card_still_detected(self, tmp_path):
        # Not in the test-PAN allowlist -> still reported
        result = self._run_on(tmp_path, "card = 4111111111111129\n", "config.py")
        assert "pii-scan:credit-card" in self._ids(result)


class TestMinifiedSkip:
    """Files with a very long single line (minified/generated blobs) are skipped
    with a MINIFIED_SKIP annotation and produce no findings."""

    def test_minified_line_skipped(self, tmp_path):
        from pii_scan.rules import default_ruleset

        # One huge line that also contains a real-looking secret
        blob = "x" * 20000 + " AKIA1234567890ABCDEF"
        (tmp_path / "bundle.min.js").write_text(blob + "\n", encoding="utf-8")
        cfg = Config(source=str(tmp_path), ruleset=default_ruleset(), redact=True)
        result = run(cfg)
        assert result.findings == []
        assert any("MINIFIED_SKIP" in e for e in result.errors)

    def test_normal_file_not_skipped(self, tmp_path):
        from pii_scan.rules import default_ruleset

        (tmp_path / "ok.py").write_text(
            "key = AKIA1234567890ABCDEF\n", encoding="utf-8"
        )
        cfg = Config(source=str(tmp_path), ruleset=default_ruleset(), redact=True)
        result = run(cfg)
        assert "pii-scan:aws-access-key-id" in [f.rule_id for f in result.findings]
        assert not any("MINIFIED_SKIP" in e for e in result.errors)


class TestEnhancements:
    def test_scan_single_file(self, tmp_path):
        f = tmp_path / "single.csv"
        f.write_text("ssn: 123-45-6789\n", encoding="utf-8")
        result = run(_make_config(str(f)))
        assert result.files_scanned == 1
        assert len(result.findings) == 1
        assert result.findings[0].rule_id == "pii-scan:ssn-simple"

    def test_multi_match_per_line_with_allowlist(self, tmp_path):
        from pii_scan.rules import default_ruleset

        f = tmp_path / "keys.py"
        # One allowlisted key and one real key on the exact same line
        f.write_text(
            'keys = ["AKIAIOSFODNN7EXAMPLE", "AKIA1234567890ABCDEF"]\n',
            encoding="utf-8",
        )
        cfg = Config(source=str(f), ruleset=default_ruleset(), redact=False)
        result = run(cfg)
        # Should detect the real key even though the allowlisted key is on the same line
        assert len(result.findings) == 1
        assert result.findings[0].redacted_match == "AKIA1234567890ABCDEF"

    def test_rule_file_extensions_filter(self, tmp_path):
        custom_yaml = b"""
version: "1"
rules:
  - id: custom-ext
    description: CSV only rule
    pattern: '\\bSECRET[0-9]{4}\\b'
    confidence: high
    severity: high
    category: credentials
    file_extensions: [".csv"]
"""
        rs = load(custom_yaml)
        (tmp_path / "data.csv").write_text("SECRET1234\n", encoding="utf-8")
        (tmp_path / "data.txt").write_text("SECRET1234\n", encoding="utf-8")
        result = run(Config(source=str(tmp_path), ruleset=rs))
        assert result.files_scanned == 2
        assert len(result.findings) == 1
        assert result.findings[0].file == "data.csv"

    def test_default_exclude_dirs(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("ssn: 123-45-6789\n", encoding="utf-8")
        (tmp_path / "valid.txt").write_text("ssn: 123-45-6789\n", encoding="utf-8")
        result = run(_make_config(str(tmp_path)))
        assert result.files_scanned == 1
        assert len(result.findings) == 1
        assert result.findings[0].file == "valid.txt"
