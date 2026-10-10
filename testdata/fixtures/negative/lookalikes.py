# Values that RESEMBLE secrets/PII but must NOT be flagged. These guard against
# the broad numeric/hex rules and the context-anchored rules firing without
# their required keyword context. Variable names here deliberately avoid the
# context keywords (ip/lat/lon/mmr/session/token/key/ein/iban/dob/xuid/...).

# UUID v4 with no advertising-id (idfa/gaid) context -> not an advertising identifier
record_uuid = "550e8400-e29b-41d4-a716-446655440000"

# Bare 32-char hex digest (MD5-shaped), no epic-account / credential-pair context
content_digest = "d41d8cd98f00b204e9800998ecf8427e"

# A private IPv4 NOT in a user-tracking variable context
cache_version = "192.168.10.20"

# 16-digit identifier that is not a valid card prefix (starts with 1)
order_reference = "1234567890123456"

# A long number that is not a SteamID64 (wrong length) and has no platform context
legacy_counter = "765611900000"

# A 9-digit number with no routing/EIN/SSN context
widget_count = 123456789

# An ISO date that is not a date-of-birth (no dob/birth context)
release_date = "2024-01-15"

# A float that is not a GPS coordinate (no lat/lon/lng context)
sensor_offset = -73.9857
