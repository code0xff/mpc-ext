-- Recovery start and device key replacement (docs/adr/0008-recovery-start-and-device-key-replacement.md).
--
-- `recovery_requests` came with the first migration and was never used. A request moves through
-- awaiting_assertion -> cooling -> completed, or ends as cancelled or expired. Times are unix
-- seconds: comparing RFC 3339 strings orders wrongly when the fractional digits differ in length.

ALTER TABLE recovery_requests ADD COLUMN new_device_key BLOB;
ALTER TABLE recovery_requests ADD COLUMN created_unix INTEGER NOT NULL DEFAULT 0;
-- While awaiting an assertion: when the request lapses. While cooling: the last moment it can be
-- completed.
ALTER TABLE recovery_requests ADD COLUMN expires_unix INTEGER NOT NULL DEFAULT 0;
-- When the cooling-off period ends. Set once the passkey assertion has been verified.
ALTER TABLE recovery_requests ADD COLUMN ready_unix INTEGER;
ALTER TABLE recovery_requests ADD COLUMN completed_at TEXT;

-- A wallet has at most one request in its cooling-off period.
CREATE UNIQUE INDEX recovery_one_cooling ON recovery_requests (wallet_id) WHERE status = 'cooling';
CREATE INDEX recovery_requests_created ON recovery_requests (wallet_id, created_unix);
