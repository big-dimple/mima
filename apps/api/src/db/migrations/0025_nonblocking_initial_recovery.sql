CREATE OR REPLACE FUNCTION mima_guard_recovery_key_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  approval_count integer;
  replacing_active_key boolean;
BEGIN
  IF NEW.ceremony_id <> OLD.ceremony_id
    OR NEW.key_fingerprint <> OLD.key_fingerprint
    OR NEW.public_encryption_key <> OLD.public_encryption_key
    OR NEW.threshold <> OLD.threshold
    OR NEW.share_count <> OLD.share_count
    OR NEW.ceremony_evidence_digest <> OLD.ceremony_evidence_digest
    OR NEW.created_by_user_id <> OLD.created_by_user_id
    OR NEW.created_at <> OLD.created_at
  THEN
    RAISE EXCEPTION 'enterprise recovery key binding is immutable';
  END IF;
  IF NOT (
    (OLD.status = 'pending' AND NEW.status IN ('pending', 'staged', 'compromised', 'cancelled'))
    OR (OLD.status = 'staged' AND NEW.status IN ('staged', 'active', 'compromised', 'cancelled'))
    OR (OLD.status = 'active' AND NEW.status IN ('active', 'retired', 'compromised'))
    OR (OLD.status = NEW.status AND OLD.status IN ('retired', 'compromised', 'cancelled'))
  ) THEN
    RAISE EXCEPTION 'invalid enterprise recovery key transition: % -> %', OLD.status, NEW.status;
  END IF;
  SELECT count(*) INTO approval_count
  FROM enterprise_recovery_key_approvals
  WHERE recovery_key_id = OLD.id
    AND ceremony_evidence_digest = OLD.ceremony_evidence_digest;
  IF NEW.status IN ('staged', 'active') AND approval_count <> 2 THEN
    RAISE EXCEPTION 'enterprise recovery key requires exactly two distinct approvals';
  END IF;
  SELECT EXISTS (
    SELECT 1 FROM enterprise_recovery_keys recovery_key
    WHERE recovery_key.id <> OLD.id
      AND recovery_key.status = 'active'
  ) INTO replacing_active_key;
  IF NEW.status = 'active' AND replacing_active_key AND EXISTS (
    SELECT 1 FROM vault_crypto_states crypto_state
    WHERE crypto_state.storage_mode = 'e2ee'
      AND NOT EXISTS (
        SELECT 1 FROM vault_key_envelopes envelope
        WHERE envelope.vault_id = crypto_state.vault_id
          AND envelope.key_epoch = crypto_state.active_epoch
          AND envelope.recipient_kind = 'enterprise_recovery'
          AND envelope.recipient_recovery_key_id = NEW.id
          AND envelope.access_scope = 'recovery'
          AND envelope.status = 'active'
          AND envelope.signer_user_id IS NOT NULL
      )
  ) THEN
    RAISE EXCEPTION 'replacement enterprise recovery key does not cover every e2ee vault';
  END IF;
  RETURN NEW;
END;
$$;
