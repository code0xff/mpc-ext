CREATE TABLE browser_ceremonies (
    session_id    TEXT PRIMARY KEY NOT NULL,
    handoff_hash  BLOB NOT NULL UNIQUE,
    wallet_id     TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('register', 'assert')),
    purpose       TEXT NOT NULL,
    operation_id  TEXT,
    digest        TEXT,
    challenge_id  TEXT,
    options       TEXT,
    expires_at    TEXT NOT NULL,
    claimed_at    TEXT,
    completed_at  TEXT,
    cancelled_at  TEXT
) STRICT;

CREATE INDEX browser_ceremonies_expiry ON browser_ceremonies (expires_at);
CREATE INDEX browser_ceremonies_wallet ON browser_ceremonies (wallet_id, session_id);
