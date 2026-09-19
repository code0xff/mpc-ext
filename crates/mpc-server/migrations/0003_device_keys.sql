CREATE TABLE device_keys (
    wallet_id   TEXT PRIMARY KEY NOT NULL,
    public_key  BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
) STRICT;

CREATE TABLE used_device_nonces (
    wallet_id  TEXT NOT NULL,
    nonce      TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (wallet_id, nonce)
) STRICT;

CREATE INDEX used_device_nonces_expiry ON used_device_nonces (expires_at);
