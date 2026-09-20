-- Recovery signing (driving the recovery share) is authorized by its own `recovery` grant, so the
-- purpose constraint has to admit it. SQLite cannot alter a CHECK, so the table is rebuilt.
CREATE TABLE passkey_authorizations_new (
    authorization_id TEXT PRIMARY KEY NOT NULL,
    wallet_id        TEXT NOT NULL,
    purpose          TEXT NOT NULL CHECK (purpose IN ('sign', 'recovery')),
    operation_id     TEXT NOT NULL,
    digest           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    consumed_at      TEXT,
    UNIQUE (wallet_id, purpose, operation_id, digest)
) STRICT;

INSERT INTO passkey_authorizations_new
    SELECT authorization_id, wallet_id, purpose, operation_id, digest, created_at, expires_at,
           consumed_at
    FROM passkey_authorizations;

DROP TABLE passkey_authorizations;
ALTER TABLE passkey_authorizations_new RENAME TO passkey_authorizations;

CREATE INDEX passkey_authorizations_lookup
    ON passkey_authorizations (wallet_id, purpose, operation_id, digest, consumed_at);
