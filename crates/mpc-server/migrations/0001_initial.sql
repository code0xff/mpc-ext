-- The server stores share C only. Shares are encrypted by the application before they get
-- here, so the database never sees a plaintext share (docs/server.md).

CREATE TABLE key_shares (
    wallet_id      TEXT PRIMARY KEY NOT NULL,
    -- The encrypted share C. Never plaintext.
    ciphertext     BLOB NOT NULL,
    nonce          BLOB NOT NULL,
    public_key     BLOB NOT NULL,
    format_version INTEGER NOT NULL,
    created_at     TEXT NOT NULL,
    refreshed_at   TEXT
) STRICT;

-- In-flight DKG sessions. Deleted once complete or expired.
CREATE TABLE dkg_sessions (
    session_id TEXT PRIMARY KEY NOT NULL,
    wallet_id  TEXT NOT NULL,
    round      INTEGER NOT NULL,
    -- Party state carried between rounds, stored sealed.
    state      BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;

CREATE INDEX dkg_sessions_expiry ON dkg_sessions (expires_at);

-- Recovery requests. Approved only after the cooling-off period.
CREATE TABLE recovery_requests (
    request_id  TEXT PRIMARY KEY NOT NULL,
    wallet_id   TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    approved_at TEXT,
    cancelled_at TEXT
) STRICT;

CREATE INDEX recovery_requests_wallet ON recovery_requests (wallet_id);

-- Append-only audit log. Never records secrets or personal data.
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    wallet_id  TEXT,
    event      TEXT NOT NULL,
    detail     TEXT,
    created_at TEXT NOT NULL
) STRICT;
