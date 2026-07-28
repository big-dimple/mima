ALTER TABLE command_dedup
  ADD COLUMN command_name text NOT NULL DEFAULT 'legacy',
  ADD COLUMN request_digest bytea;
ALTER TABLE command_dedup
  ADD CONSTRAINT command_dedup_request_digest_ck
  CHECK (request_digest IS NULL OR octet_length(request_digest) = 32);
ALTER TABLE command_dedup DROP CONSTRAINT command_dedup_pkey;
CREATE UNIQUE INDEX command_dedup_uq
  ON command_dedup (idempotency_key, user_id, command_name);

ALTER TABLE vault_key_envelopes
  ADD COLUMN signer_user_id text REFERENCES users(id) ON DELETE RESTRICT,
  ADD COLUMN signer_key_version integer,
  ADD COLUMN signer_public_key bytea,
  ADD CONSTRAINT vault_key_envelopes_signer_snapshot_ck CHECK (
    (signer_user_id IS NULL AND signer_key_version IS NULL AND signer_public_key IS NULL)
    OR (
      signer_user_id IS NOT NULL
      AND signer_key_version > 0
      AND octet_length(signer_public_key) = 32
    )
  );

CREATE OR REPLACE FUNCTION mima_guard_envelope_signer_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.signer_user_id IS NULL THEN
    RAISE EXCEPTION 'vault envelope signer snapshot is required';
  END IF;
  IF NEW.signer_user_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM user_devices device
    WHERE device.id = NEW.sender_device_id
      AND device.user_id = NEW.signer_user_id
  ) THEN
    RAISE EXCEPTION 'vault envelope signer does not own sender device';
  END IF;
  IF NEW.signer_user_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM user_crypto_profiles profile
    WHERE profile.user_id = NEW.signer_user_id
      AND profile.crypto_generation = NEW.signer_key_version
      AND profile.public_signing_key = NEW.signer_public_key
  ) THEN
    RAISE EXCEPTION 'vault envelope signer snapshot does not match the active profile';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.signer_user_id IS NOT NULL AND (
    NEW.signer_user_id IS DISTINCT FROM OLD.signer_user_id
    OR NEW.signer_key_version IS DISTINCT FROM OLD.signer_key_version
    OR NEW.signer_public_key IS DISTINCT FROM OLD.signer_public_key
  ) THEN
    RAISE EXCEPTION 'vault envelope signer snapshot is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER vault_key_envelopes_signer_snapshot_guard
BEFORE INSERT OR UPDATE OF signer_user_id, signer_key_version, signer_public_key
ON vault_key_envelopes
FOR EACH ROW EXECUTE FUNCTION mima_guard_envelope_signer_snapshot();

ALTER TABLE enterprise_recovery_keys
  ADD COLUMN cancelled_at timestamptz;
ALTER TABLE enterprise_recovery_keys
  DROP CONSTRAINT enterprise_recovery_keys_status_check,
  ADD CONSTRAINT enterprise_recovery_keys_status_check
    CHECK (status IN ('pending', 'staged', 'active', 'retired', 'compromised', 'cancelled'));
CREATE OR REPLACE FUNCTION mima_guard_recovery_key_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  recovery_key enterprise_recovery_keys%ROWTYPE;
  approval_count integer;
BEGIN
  SELECT * INTO recovery_key FROM enterprise_recovery_keys
  WHERE id = NEW.recovery_key_id FOR UPDATE;
  IF recovery_key.id IS NULL OR recovery_key.status NOT IN ('pending', 'staged') THEN
    RAISE EXCEPTION 'enterprise recovery key is not open for approval';
  END IF;
  IF NEW.ceremony_evidence_digest <> recovery_key.ceremony_evidence_digest THEN
    RAISE EXCEPTION 'enterprise recovery key approval digest does not match';
  END IF;
  IF NOT mima_is_platform_admin(NEW.approver_user_id) THEN
    RAISE EXCEPTION 'enterprise recovery key approval requires platform-admin';
  END IF;
  SELECT count(*) INTO approval_count
  FROM enterprise_recovery_key_approvals
  WHERE recovery_key_id = NEW.recovery_key_id;
  IF approval_count >= 2 THEN
    RAISE EXCEPTION 'enterprise recovery key already has two approvals';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_recovery_key_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  approval_count integer;
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
  IF NEW.status = 'active' AND EXISTS (
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
    RAISE EXCEPTION 'enterprise recovery key does not cover every e2ee vault';
  END IF;
  RETURN NEW;
END;
$$;

WITH ranked_drafts AS (
  SELECT id, row_number() OVER (
    ORDER BY CASE status WHEN 'staged' THEN 0 ELSE 1 END, created_at DESC, id DESC
  ) AS draft_rank
  FROM enterprise_recovery_keys
  WHERE status IN ('pending', 'staged')
)
UPDATE enterprise_recovery_keys recovery_key
SET status = 'cancelled', cancelled_at = NULL
FROM ranked_drafts
WHERE recovery_key.id = ranked_drafts.id
  AND ranked_drafts.draft_rank > 1;

CREATE UNIQUE INDEX enterprise_recovery_keys_draft_uq
  ON enterprise_recovery_keys ((true))
  WHERE status IN ('pending', 'staged');

ALTER TABLE enterprise_recovery_requests
  ADD COLUMN key_epoch integer,
  ADD COLUMN expired_at timestamptz;

DROP TRIGGER enterprise_recovery_requests_guard_update ON enterprise_recovery_requests;

UPDATE enterprise_recovery_requests request
SET status = 'cancelled',
    cancelled_at = NULL,
    last_error_code = 'upgrade_missing_key_epoch'
WHERE status IN ('pending', 'approved');

UPDATE enterprise_recovery_requests request
SET key_epoch = COALESCE(
  (SELECT envelope.key_epoch FROM vault_key_envelopes envelope
   WHERE envelope.id = request.completed_envelope_id),
  (SELECT crypto_state.active_epoch FROM vault_crypto_states crypto_state
   WHERE crypto_state.vault_id = request.vault_id)
);

ALTER TABLE enterprise_recovery_requests
  ALTER COLUMN key_epoch SET NOT NULL,
  ADD CONSTRAINT enterprise_recovery_requests_epoch_fk
    FOREIGN KEY (vault_id, key_epoch)
    REFERENCES vault_key_epochs(vault_id, epoch) ON DELETE RESTRICT,
  DROP CONSTRAINT enterprise_recovery_requests_status_check,
  ADD CONSTRAINT enterprise_recovery_requests_status_check
    CHECK (status IN ('pending', 'approved', 'completed', 'cancelled', 'expired', 'failed'));

CREATE OR REPLACE FUNCTION mima_guard_recovery_request_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  UPDATE enterprise_recovery_requests
  SET status = 'expired', expired_at = now(), last_error_code = 'request_expired'
  WHERE vault_id = NEW.vault_id
    AND target_user_id = NEW.target_user_id
    AND status IN ('pending', 'approved')
    AND expires_at <= now();
  IF NOT EXISTS (
    SELECT 1 FROM user_devices device
    WHERE device.id = NEW.target_device_id
      AND device.user_id = NEW.target_user_id
      AND device.status = 'active'
  ) THEN
    RAISE EXCEPTION 'recovery target device is not active';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM user_crypto_profiles profile
    WHERE profile.user_id = NEW.target_user_id
      AND profile.crypto_generation = NEW.target_key_version
      AND profile.public_encryption_key = NEW.target_encryption_public_key
  ) THEN
    RAISE EXCEPTION 'recovery target user public key or generation does not match';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM enterprise_recovery_keys recovery_key
    WHERE recovery_key.id = NEW.recovery_key_id AND recovery_key.status = 'active'
  ) THEN
    RAISE EXCEPTION 'enterprise recovery key is not active';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM vault_crypto_states crypto_state
    WHERE crypto_state.vault_id = NEW.vault_id
      AND crypto_state.storage_mode = 'e2ee'
      AND crypto_state.active_epoch = NEW.key_epoch
  ) THEN
    RAISE EXCEPTION 'recovery request epoch is not active';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_recovery_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  recovery_request enterprise_recovery_requests%ROWTYPE;
  approval_count integer;
BEGIN
  SELECT * INTO recovery_request FROM enterprise_recovery_requests
  WHERE id = NEW.request_id FOR UPDATE;
  IF recovery_request.id IS NULL
    OR recovery_request.status NOT IN ('pending', 'approved')
    OR recovery_request.expires_at <= now()
  THEN
    RAISE EXCEPTION 'enterprise recovery request is not open for approval';
  END IF;
  IF NEW.request_digest <> recovery_request.request_digest THEN
    RAISE EXCEPTION 'enterprise recovery approval digest does not match request';
  END IF;
  IF NEW.approver_user_id = recovery_request.target_user_id THEN
    RAISE EXCEPTION 'enterprise recovery target cannot approve their own request';
  END IF;
  IF NOT mima_is_platform_admin(NEW.approver_user_id) THEN
    RAISE EXCEPTION 'enterprise recovery approval requires platform-admin';
  END IF;
  SELECT count(*) INTO approval_count FROM enterprise_recovery_approvals
  WHERE request_id = NEW.request_id;
  IF approval_count >= 2 THEN
    RAISE EXCEPTION 'enterprise recovery request already has two approvals';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_recovery_request_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  approval_count integer;
BEGIN
  IF OLD.status IN ('completed', 'cancelled', 'expired', 'failed') THEN
    RAISE EXCEPTION 'completed enterprise recovery request is immutable';
  END IF;
  IF NOT (
    (OLD.status = 'pending' AND NEW.status IN ('pending', 'approved', 'cancelled', 'expired', 'failed'))
    OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'completed', 'cancelled', 'expired', 'failed'))
  ) THEN
    RAISE EXCEPTION 'invalid enterprise recovery state transition: % -> %', OLD.status, NEW.status;
  END IF;
  IF NEW.request_digest <> OLD.request_digest
    OR NEW.vault_id <> OLD.vault_id
    OR NEW.key_epoch <> OLD.key_epoch
    OR NEW.recovery_key_id <> OLD.recovery_key_id
    OR NEW.target_user_id <> OLD.target_user_id
    OR NEW.target_device_id <> OLD.target_device_id
    OR NEW.target_encryption_public_key <> OLD.target_encryption_public_key
    OR NEW.target_key_version <> OLD.target_key_version
    OR NEW.reason <> OLD.reason
    OR NEW.created_by_user_id <> OLD.created_by_user_id
    OR NEW.created_at <> OLD.created_at
    OR NEW.expires_at <> OLD.expires_at
  THEN
    RAISE EXCEPTION 'enterprise recovery request binding is immutable';
  END IF;
  SELECT count(*) INTO approval_count FROM enterprise_recovery_approvals
  WHERE request_id = OLD.id AND request_digest = OLD.request_digest;
  IF NEW.status IN ('approved', 'completed') AND approval_count <> 2 THEN
    RAISE EXCEPTION 'enterprise recovery requires exactly two distinct approvals';
  END IF;
  IF NEW.status = 'completed' THEN
    IF NEW.expires_at <= now() THEN
      RAISE EXCEPTION 'enterprise recovery request has expired';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM vault_key_envelopes envelope
      WHERE envelope.id = NEW.completed_envelope_id
        AND envelope.vault_id = NEW.vault_id
        AND envelope.key_epoch = NEW.key_epoch
        AND envelope.recipient_kind = 'user'
        AND envelope.recipient_user_id = NEW.target_user_id
        AND envelope.authorization_kind = 'recovery'
        AND envelope.access_scope = NEW.target_capability
        AND envelope.status = 'active'
        AND envelope.signer_user_id IS NOT NULL
    ) THEN
      RAISE EXCEPTION 'completed enterprise recovery envelope does not match request';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_requests_guard_update
BEFORE UPDATE ON enterprise_recovery_requests
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_request_update();

ALTER TABLE account_crypto_reset_requests
  ADD COLUMN expired_at timestamptz;
ALTER TABLE account_crypto_reset_requests
  DROP CONSTRAINT account_crypto_reset_requests_status_check,
  ADD CONSTRAINT account_crypto_reset_requests_status_check
    CHECK (status IN ('pending', 'approved', 'activated', 'cancelled', 'expired', 'failed'));

CREATE OR REPLACE FUNCTION mima_guard_account_crypto_reset_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  reset_request account_crypto_reset_requests%ROWTYPE;
  approval_count integer;
BEGIN
  SELECT * INTO reset_request FROM account_crypto_reset_requests
  WHERE id = NEW.request_id FOR UPDATE;
  IF reset_request.id IS NULL
    OR reset_request.status NOT IN ('pending', 'approved')
    OR reset_request.expires_at <= now()
  THEN
    RAISE EXCEPTION 'account crypto reset is not open for approval';
  END IF;
  IF NEW.request_digest <> reset_request.request_digest THEN
    RAISE EXCEPTION 'account crypto reset approval digest does not match';
  END IF;
  IF NEW.approver_user_id = reset_request.target_user_id THEN
    RAISE EXCEPTION 'account crypto reset target cannot approve their own request';
  END IF;
  IF NOT mima_is_platform_admin(NEW.approver_user_id) THEN
    RAISE EXCEPTION 'account crypto reset approval requires platform-admin';
  END IF;
  SELECT count(*) INTO approval_count FROM account_crypto_reset_approvals
  WHERE request_id = NEW.request_id;
  IF approval_count >= 2 THEN
    RAISE EXCEPTION 'account crypto reset already has two approvals';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_account_crypto_reset_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  current_profile user_crypto_profiles%ROWTYPE;
BEGIN
  UPDATE account_crypto_reset_requests
  SET status = 'expired', expired_at = now(), last_error_code = 'request_expired'
  WHERE target_user_id = NEW.target_user_id
    AND status IN ('pending', 'approved')
    AND expires_at <= now();
  SELECT * INTO current_profile FROM user_crypto_profiles
  WHERE user_id = NEW.target_user_id FOR UPDATE;
  IF current_profile.user_id IS NULL
    OR current_profile.profile_version <> NEW.expected_profile_version
    OR current_profile.crypto_generation <> NEW.expected_crypto_generation
  THEN
    RAISE EXCEPTION 'account crypto reset profile generation does not match';
  END IF;
  IF current_profile.public_encryption_key = NEW.public_encryption_key
    OR current_profile.public_signing_key = NEW.public_signing_key
  THEN
    RAISE EXCEPTION 'account crypto reset must use new user keys';
  END IF;
  IF EXISTS (SELECT 1 FROM user_devices WHERE id = NEW.candidate_device_id) THEN
    RAISE EXCEPTION 'account crypto reset candidate device already exists';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_account_crypto_reset_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  approval_count integer;
BEGIN
  IF OLD.status IN ('activated', 'cancelled', 'expired', 'failed') THEN
    RAISE EXCEPTION 'completed account crypto reset is immutable';
  END IF;
  IF NOT (
    (OLD.status = 'pending' AND NEW.status IN ('pending', 'approved', 'cancelled', 'expired', 'failed'))
    OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'activated', 'cancelled', 'expired', 'failed'))
  ) THEN
    RAISE EXCEPTION 'invalid account crypto reset transition: % -> %', OLD.status, NEW.status;
  END IF;
  IF NEW.target_user_id IS DISTINCT FROM OLD.target_user_id
    OR NEW.expected_profile_version IS DISTINCT FROM OLD.expected_profile_version
    OR NEW.expected_crypto_generation IS DISTINCT FROM OLD.expected_crypto_generation
    OR NEW.new_crypto_generation IS DISTINCT FROM OLD.new_crypto_generation
    OR NEW.protocol_version IS DISTINCT FROM OLD.protocol_version
    OR NEW.kdf_algorithm IS DISTINCT FROM OLD.kdf_algorithm
    OR NEW.kdf_memory_kib IS DISTINCT FROM OLD.kdf_memory_kib
    OR NEW.kdf_iterations IS DISTINCT FROM OLD.kdf_iterations
    OR NEW.kdf_parallelism IS DISTINCT FROM OLD.kdf_parallelism
    OR NEW.kdf_salt IS DISTINCT FROM OLD.kdf_salt
    OR NEW.wrapped_account_key_ciphertext IS DISTINCT FROM OLD.wrapped_account_key_ciphertext
    OR NEW.wrapped_account_key_nonce IS DISTINCT FROM OLD.wrapped_account_key_nonce
    OR NEW.public_encryption_key IS DISTINCT FROM OLD.public_encryption_key
    OR NEW.public_signing_key IS DISTINCT FROM OLD.public_signing_key
    OR NEW.signing_key_fingerprint IS DISTINCT FROM OLD.signing_key_fingerprint
    OR NEW.candidate_device_id IS DISTINCT FROM OLD.candidate_device_id
    OR NEW.candidate_device_type IS DISTINCT FROM OLD.candidate_device_type
    OR NEW.candidate_device_encryption_public_key IS DISTINCT FROM OLD.candidate_device_encryption_public_key
    OR NEW.candidate_device_signing_public_key IS DISTINCT FROM OLD.candidate_device_signing_public_key
    OR NEW.candidate_device_key_fingerprint IS DISTINCT FROM OLD.candidate_device_key_fingerprint
    OR NEW.candidate_device_encrypted_label IS DISTINCT FROM OLD.candidate_device_encrypted_label
    OR NEW.candidate_device_label_nonce IS DISTINCT FROM OLD.candidate_device_label_nonce
    OR NEW.candidate_device_certificate_payload IS DISTINCT FROM OLD.candidate_device_certificate_payload
    OR NEW.candidate_device_certificate_signature IS DISTINCT FROM OLD.candidate_device_certificate_signature
    OR NEW.candidate_user_proof IS DISTINCT FROM OLD.candidate_user_proof
    OR NEW.request_digest IS DISTINCT FROM OLD.request_digest
    OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
  THEN
    RAISE EXCEPTION 'account crypto reset binding is immutable';
  END IF;
  SELECT count(*) INTO approval_count FROM account_crypto_reset_approvals
  WHERE request_id = OLD.id AND request_digest = OLD.request_digest;
  IF NEW.status IN ('approved', 'activated') AND approval_count <> 2 THEN
    RAISE EXCEPTION 'account crypto reset requires exactly two distinct approvals';
  END IF;
  IF NEW.status = 'activated' THEN
    IF NEW.expires_at <= now() THEN
      RAISE EXCEPTION 'account crypto reset has expired';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM user_crypto_profiles profile
      WHERE profile.user_id = NEW.target_user_id
        AND profile.profile_version = NEW.expected_profile_version + 1
        AND profile.crypto_generation = NEW.new_crypto_generation
        AND profile.public_encryption_key = NEW.public_encryption_key
        AND profile.public_signing_key = NEW.public_signing_key
    ) OR NOT EXISTS (
      SELECT 1 FROM user_devices device
      WHERE device.id = NEW.candidate_device_id
        AND device.user_id = NEW.target_user_id
        AND device.status = 'active'
        AND device.device_generation = NEW.new_crypto_generation
        AND device.public_encryption_key = NEW.candidate_device_encryption_public_key
        AND device.public_signing_key = NEW.candidate_device_signing_public_key
    ) THEN
      RAISE EXCEPTION 'activated account crypto reset does not match active profile or device';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_active_recovery_coverage()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  active_recovery_key_id uuid;
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended(current_database() || ':mima:enterprise-recovery-coverage', 0)
  );
  SELECT id INTO active_recovery_key_id FROM enterprise_recovery_keys
  WHERE status = 'active' LIMIT 1;
  IF active_recovery_key_id IS NOT NULL AND (
    NEW.active_epoch IS NULL OR NOT EXISTS (
      SELECT 1 FROM vault_key_envelopes envelope
      WHERE envelope.vault_id = NEW.vault_id
        AND envelope.key_epoch = NEW.active_epoch
        AND envelope.recipient_kind = 'enterprise_recovery'
        AND envelope.recipient_recovery_key_id = active_recovery_key_id
        AND envelope.access_scope = 'recovery'
        AND envelope.status = 'active'
        AND envelope.signer_user_id IS NOT NULL
    )
  ) THEN
    RAISE EXCEPTION 'active enterprise recovery key must cover the e2ee vault epoch';
  END IF;
  RETURN NEW;
END;
$$;
