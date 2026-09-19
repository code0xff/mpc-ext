CREATE TABLE passkey_authorizations (
    authorization_id TEXT PRIMARY KEY NOT NULL,
    wallet_id        TEXT NOT NULL,
    purpose          TEXT NOT NULL CHECK (purpose = 'sign'),
    operation_id     TEXT NOT NULL,
    digest           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    consumed_at      TEXT,
    UNIQUE (wallet_id, purpose, operation_id, digest)
) STRICT;

CREATE INDEX passkey_authorizations_lookup
    ON passkey_authorizations (wallet_id, purpose, operation_id, digest, consumed_at);
