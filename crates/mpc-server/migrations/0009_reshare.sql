-- Distributed reshare (docs/adr/0007-distributed-reshare.md).
--
-- The new share is staged next to the live one and swapped in only on an explicit commit, so a
-- reshare that stops halfway leaves the previous share valid.

-- In-flight reshare sessions, kept separate from DKG so a DKG round can never be pointed at one.
CREATE TABLE reshare_sessions (
    reshare_id TEXT PRIMARY KEY NOT NULL,
    wallet_id  TEXT NOT NULL,
    round      INTEGER NOT NULL,
    -- Party state carried between rounds, stored sealed.
    state      BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;

CREATE INDEX reshare_sessions_expiry ON reshare_sessions (expires_at);

-- The share produced by a finished reshare, waiting for the commit. One per wallet.
CREATE TABLE pending_reshares (
    wallet_id  TEXT PRIMARY KEY NOT NULL,
    reshare_id TEXT NOT NULL,
    -- The encrypted new share. Never plaintext.
    ciphertext BLOB NOT NULL,
    nonce      BLOB NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
) STRICT;

CREATE INDEX pending_reshares_expiry ON pending_reshares (expires_at);
