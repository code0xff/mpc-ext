-- Seeing and cancelling a recovery with the passkey alone
-- (docs/adr/0009-managing-recoveries-with-the-passkey.md).

-- The passkey's user handle, so a usernameless assertion can be traced back to its wallet. It is 64
-- random bytes chosen at registration, and it is also inside the credential blob. This column only
-- exists to be looked up by. Credentials that predate it are filled in when the server starts.
ALTER TABLE passkey_credentials ADD COLUMN user_handle BLOB;
CREATE UNIQUE INDEX passkey_credentials_user_handle
    ON passkey_credentials (user_handle) WHERE user_handle IS NOT NULL;

-- A short session opened by one passkey assertion on the management page. Only a hash of the
-- session token is stored, so the table cannot be used to act as anyone.
CREATE TABLE manage_sessions (
    session_hash BLOB PRIMARY KEY NOT NULL,
    wallet_id    TEXT NOT NULL,
    expires_unix INTEGER NOT NULL
) STRICT;

CREATE INDEX manage_sessions_expiry ON manage_sessions (expires_unix);
