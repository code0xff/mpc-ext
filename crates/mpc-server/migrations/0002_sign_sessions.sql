-- In-flight signing sessions. The server keeps no state between HTTP requests, so the party
-- state is sealed and parked here between rounds (docs/server.md).
CREATE TABLE sign_sessions (
    sign_id    TEXT PRIMARY KEY NOT NULL,
    wallet_id  TEXT NOT NULL,
    round      INTEGER NOT NULL,
    -- Sealed SignParty state. It contains the key share, so it is never stored in the clear.
    state      BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    -- The digest being signed, kept for the audit log.
    digest     BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;

CREATE INDEX sign_sessions_expiry ON sign_sessions (expires_at);
