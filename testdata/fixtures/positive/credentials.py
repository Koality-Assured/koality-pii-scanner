# SYNTHETIC test fixture — NOT real credentials. Used only to validate that the
# PII scanner DETECTS these credential patterns. None of these are live secrets.

# AWS access key id (AKIA + 16, not the AWS docs EXAMPLE form -> must be detected)
AWS_ACCESS_KEY_ID = "AKIAZ3FAKE7TESTKEY01"

# GitHub personal access token (ghp_ + 36+; synthetic, fails GitHub checksum)
GITHUB_TOKEN = "ghp_FAKE0000000000000000000000000000TEST"

# Hardcoded bearer / api key assignment (matches the bearer-token rule)
api_key = "abcdefghij1234567890ABCDEFGHIJ"

# JSON Web Token (synthetic three-part structure)
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIifQ.c2lnbmF0dXJlLXBsYWNlaG9sZGVy"

# PEM private key header (block header alone is enough to flag)
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
(synthetic placeholder — no real key material)
-----END RSA PRIVATE KEY-----"""
