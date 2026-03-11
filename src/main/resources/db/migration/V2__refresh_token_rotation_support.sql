ALTER TABLE refresh_tokens
    ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS replaced_by_token_hash VARCHAR(128);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expiry_date ON refresh_tokens (expiry_date);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_device_active
    ON refresh_tokens (user_id, device_id)
    WHERE revoked_at IS NULL;
