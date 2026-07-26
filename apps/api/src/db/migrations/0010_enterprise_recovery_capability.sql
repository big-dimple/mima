ALTER TABLE enterprise_recovery_requests
  ADD COLUMN target_capability text;

UPDATE enterprise_recovery_requests
SET target_capability = 'full'
WHERE target_capability IS NULL;

ALTER TABLE enterprise_recovery_requests
  ALTER COLUMN target_capability SET NOT NULL;

ALTER TABLE enterprise_recovery_requests
  ADD CONSTRAINT enterprise_recovery_requests_target_capability_ck
  CHECK (target_capability IN ('metadata', 'full'));

CREATE OR REPLACE FUNCTION mima_guard_recovery_request_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  approval_count integer;
BEGIN
  IF OLD.status IN ('completed', 'cancelled', 'failed') THEN
    RAISE EXCEPTION 'completed enterprise recovery request is immutable';
  END IF;
  IF NOT (
    (OLD.status = 'pending' AND NEW.status IN ('pending', 'approved', 'cancelled', 'failed'))
    OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'completed', 'cancelled', 'failed'))
  ) THEN
    RAISE EXCEPTION 'invalid enterprise recovery state transition: % -> %', OLD.status, NEW.status;
  END IF;
  IF NEW.request_digest <> OLD.request_digest
    OR NEW.vault_id <> OLD.vault_id
    OR NEW.recovery_key_id <> OLD.recovery_key_id
    OR NEW.target_user_id <> OLD.target_user_id
    OR NEW.target_device_id <> OLD.target_device_id
    OR NEW.target_encryption_public_key <> OLD.target_encryption_public_key
    OR NEW.target_key_version <> OLD.target_key_version
    OR NEW.target_capability <> OLD.target_capability
    OR NEW.reason <> OLD.reason
    OR NEW.created_by_user_id <> OLD.created_by_user_id
    OR NEW.created_at <> OLD.created_at
    OR NEW.expires_at <> OLD.expires_at
  THEN
    RAISE EXCEPTION 'enterprise recovery request binding is immutable';
  END IF;
  SELECT count(*) INTO approval_count
  FROM enterprise_recovery_approvals approval
  WHERE approval.request_id = OLD.id AND approval.request_digest = OLD.request_digest;
  IF NEW.status IN ('approved', 'completed') AND approval_count < 2 THEN
    RAISE EXCEPTION 'enterprise recovery requires two distinct approvals';
  END IF;
  IF NEW.status = 'completed' THEN
    IF NEW.expires_at <= now() THEN
      RAISE EXCEPTION 'enterprise recovery request has expired';
    END IF;
    IF NOT EXISTS (
      SELECT 1
      FROM vault_key_envelopes envelope
      JOIN vault_crypto_states crypto_state ON crypto_state.vault_id = envelope.vault_id
      WHERE envelope.id = NEW.completed_envelope_id
        AND envelope.vault_id = NEW.vault_id
        AND envelope.key_epoch = crypto_state.active_epoch
        AND envelope.recipient_kind = 'user'
        AND envelope.recipient_user_id = NEW.target_user_id
        AND envelope.authorization_kind = 'recovery'
        AND envelope.access_scope = NEW.target_capability
        AND envelope.status = 'active'
    ) THEN
      RAISE EXCEPTION 'completed enterprise recovery envelope does not match request';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
