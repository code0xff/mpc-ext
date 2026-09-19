ALTER TABLE passkey_challenges ADD COLUMN binding BLOB NOT NULL DEFAULT X'';

CREATE INDEX passkey_challenges_wallet_purpose
    ON passkey_challenges (wallet_id, purpose, used_at);
