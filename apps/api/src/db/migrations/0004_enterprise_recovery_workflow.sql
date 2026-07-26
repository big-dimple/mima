ALTER TABLE enterprise_recovery_keys
  ADD COLUMN ceremony_id text NOT NULL CHECK (char_length(ceremony_id) BETWEEN 1 AND 200),
  ADD COLUMN created_by_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  ALTER COLUMN status SET DEFAULT 'pending',
  DROP CONSTRAINT enterprise_recovery_keys_status_check,
  ADD CONSTRAINT enterprise_recovery_keys_status_check
    CHECK (status IN ('pending', 'staged', 'active', 'retired', 'compromised'));
CREATE UNIQUE INDEX enterprise_recovery_keys_ceremony_uq ON enterprise_recovery_keys (ceremony_id);

CREATE TABLE enterprise_recovery_key_approvals (
  recovery_key_id uuid NOT NULL REFERENCES enterprise_recovery_keys(id) ON DELETE RESTRICT,
  approver_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  ceremony_evidence_digest bytea NOT NULL CHECK (octet_length(ceremony_evidence_digest) = 32),
  approved_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (recovery_key_id, approver_user_id)
);

CREATE OR REPLACE FUNCTION mima_guard_recovery_key_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  recovery_key enterprise_recovery_keys%ROWTYPE;
BEGIN
  SELECT * INTO recovery_key FROM enterprise_recovery_keys
  WHERE id = NEW.recovery_key_id FOR UPDATE;
  IF recovery_key.id IS NULL OR recovery_key.status NOT IN ('pending', 'staged') THEN
    RAISE EXCEPTION 'enterprise recovery key is not open for approval';
  END IF;
  IF NEW.ceremony_evidence_digest <> recovery_key.ceremony_evidence_digest THEN
    RAISE EXCEPTION 'enterprise recovery key approval digest does not match';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM system_role_assignments assignment
    WHERE assignment.user_id = NEW.approver_user_id AND assignment.role = 'platform-admin'
  ) THEN
    RAISE EXCEPTION 'enterprise recovery key approval requires platform-admin';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_key_approvals_guard_insert
BEFORE INSERT ON enterprise_recovery_key_approvals
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_key_approval();

CREATE OR REPLACE FUNCTION mima_stage_recovery_key()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF (
    SELECT count(*) FROM enterprise_recovery_key_approvals approval
    WHERE approval.recovery_key_id = NEW.recovery_key_id
      AND approval.ceremony_evidence_digest = NEW.ceremony_evidence_digest
  ) >= 2 THEN
    UPDATE enterprise_recovery_keys SET status = 'staged'
    WHERE id = NEW.recovery_key_id AND status = 'pending';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_key_approvals_stage
AFTER INSERT ON enterprise_recovery_key_approvals
FOR EACH ROW EXECUTE FUNCTION mima_stage_recovery_key();

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
    (OLD.status = 'pending' AND NEW.status IN ('pending', 'staged', 'compromised'))
    OR (OLD.status = 'staged' AND NEW.status IN ('staged', 'active', 'compromised'))
    OR (OLD.status = 'active' AND NEW.status IN ('active', 'retired', 'compromised'))
  ) THEN
    RAISE EXCEPTION 'invalid enterprise recovery key transition: % -> %', OLD.status, NEW.status;
  END IF;
  SELECT count(*) INTO approval_count
  FROM enterprise_recovery_key_approvals approval
  WHERE approval.recovery_key_id = OLD.id
    AND approval.ceremony_evidence_digest = OLD.ceremony_evidence_digest;
  IF NEW.status IN ('staged', 'active') AND approval_count < 2 THEN
    RAISE EXCEPTION 'enterprise recovery key requires two distinct approvals';
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
      )
  ) THEN
    RAISE EXCEPTION 'enterprise recovery key does not cover every e2ee vault';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_keys_guard_update
BEFORE UPDATE ON enterprise_recovery_keys
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_key_update();

CREATE OR REPLACE FUNCTION mima_prevent_recovery_key_approval_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'enterprise recovery key approvals are append-only';
END;
$$;

CREATE TRIGGER enterprise_recovery_key_approvals_guard_update
BEFORE UPDATE OR DELETE ON enterprise_recovery_key_approvals
FOR EACH ROW EXECUTE FUNCTION mima_prevent_recovery_key_approval_change();

CREATE UNIQUE INDEX user_devices_id_user_uq ON user_devices (id, user_id);

CREATE TABLE enterprise_recovery_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE RESTRICT,
  recovery_key_id uuid NOT NULL REFERENCES enterprise_recovery_keys(id) ON DELETE RESTRICT,
  target_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  target_device_id uuid NOT NULL,
  target_encryption_public_key bytea NOT NULL CHECK (octet_length(target_encryption_public_key) = 32),
  target_key_version integer NOT NULL CHECK (target_key_version > 0),
  reason text NOT NULL CHECK (reason IN ('lost_all_devices', 'suspected_compromise', 'account_reset')),
  request_digest bytea NOT NULL UNIQUE CHECK (octet_length(request_digest) = 32),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'completed', 'cancelled', 'failed')),
  created_by_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  completed_envelope_id uuid REFERENCES vault_key_envelopes(id) ON DELETE RESTRICT,
  tool_evidence_digest bytea CHECK (tool_evidence_digest IS NULL OR octet_length(tool_evidence_digest) = 32),
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  approved_at timestamptz,
  completed_at timestamptz,
  cancelled_at timestamptz,
  failed_at timestamptz,
  FOREIGN KEY (target_device_id, target_user_id)
    REFERENCES user_devices(id, user_id) ON DELETE RESTRICT,
  CHECK (expires_at > created_at),
  CHECK (
    (status <> 'completed')
    OR (completed_envelope_id IS NOT NULL AND tool_evidence_digest IS NOT NULL AND completed_at IS NOT NULL)
  )
);
CREATE UNIQUE INDEX enterprise_recovery_requests_active_uq
  ON enterprise_recovery_requests (vault_id, target_user_id)
  WHERE status IN ('pending', 'approved');
CREATE INDEX enterprise_recovery_requests_target_idx
  ON enterprise_recovery_requests (target_user_id, status, expires_at);

CREATE TABLE enterprise_recovery_approvals (
  request_id uuid NOT NULL REFERENCES enterprise_recovery_requests(id) ON DELETE RESTRICT,
  approver_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  approved_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (request_id, approver_user_id)
);

CREATE OR REPLACE FUNCTION mima_guard_recovery_request_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
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
    WHERE crypto_state.vault_id = NEW.vault_id AND crypto_state.storage_mode = 'e2ee'
  ) THEN
    RAISE EXCEPTION 'only e2ee vaults can enter enterprise recovery';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_requests_guard_insert
BEFORE INSERT ON enterprise_recovery_requests
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_request_insert();

CREATE OR REPLACE FUNCTION mima_guard_recovery_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  recovery_request enterprise_recovery_requests%ROWTYPE;
BEGIN
  SELECT * INTO recovery_request
  FROM enterprise_recovery_requests
  WHERE id = NEW.request_id
  FOR UPDATE;
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
  IF NOT EXISTS (
    SELECT 1 FROM system_role_assignments assignment
    WHERE assignment.user_id = NEW.approver_user_id AND assignment.role = 'platform-admin'
  ) THEN
    RAISE EXCEPTION 'enterprise recovery approval requires platform-admin';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_approvals_guard_insert
BEFORE INSERT ON enterprise_recovery_approvals
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_approval();

CREATE OR REPLACE FUNCTION mima_advance_recovery_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF (
    SELECT count(*) FROM enterprise_recovery_approvals approval
    WHERE approval.request_id = NEW.request_id
  ) >= 2 THEN
    UPDATE enterprise_recovery_requests
    SET status = 'approved', approved_at = COALESCE(approved_at, now())
    WHERE id = NEW.request_id AND status = 'pending';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_approvals_advance
AFTER INSERT ON enterprise_recovery_approvals
FOR EACH ROW EXECUTE FUNCTION mima_advance_recovery_approval();

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
        AND envelope.access_scope = 'full'
        AND envelope.status = 'active'
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

CREATE OR REPLACE FUNCTION mima_prevent_recovery_approval_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'enterprise recovery approvals are append-only';
END;
$$;

CREATE TRIGGER enterprise_recovery_approvals_guard_update
BEFORE UPDATE OR DELETE ON enterprise_recovery_approvals
FOR EACH ROW EXECUTE FUNCTION mima_prevent_recovery_approval_change();
