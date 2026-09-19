CREATE TABLE passkey_credentials (
    wallet_id    TEXT PRIMARY KEY NOT NULL,
    credential   BLOB NOT NULL,
    sign_count   INTEGER NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
) STRICT;

CREATE TABLE passkey_challenges (
    challenge_id TEXT PRIMARY KEY NOT NULL,
    wallet_id    TEXT NOT NULL,
    purpose      TEXT NOT NULL,
    challenge    BLOB NOT NULL,
    expires_at   TEXT NOT NULL,
    used_at      TEXT
) STRICT;

CREATE INDEX passkey_challenges_expiry ON passkey_challenges (expires_at);
