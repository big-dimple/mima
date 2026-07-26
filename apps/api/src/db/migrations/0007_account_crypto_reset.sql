CREATE TABLE account_crypto_reset_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  expected_profile_version integer NOT NULL CHECK (expected_profile_version > 0),
  expected_crypto_generation integer NOT NULL CHECK (expected_crypto_generation > 0),
  new_crypto_generation integer NOT NULL CHECK (new_crypto_generation = expected_crypto_generation + 1),
  protocol_version text NOT NULL DEFAULT 'lm-e2ee-v1' CHECK (protocol_version = 'lm-e2ee-v1'),
  kdf_algorithm text NOT NULL DEFAULT 'argon2id13' CHECK (kdf_algorithm = 'argon2id13'),
  kdf_memory_kib integer NOT NULL CHECK (kdf_memory_kib >= 65536),
  kdf_iterations integer NOT NULL CHECK (kdf_iterations >= 3),
  kdf_parallelism integer NOT NULL CHECK (kdf_parallelism > 0),
  kdf_salt bytea NOT NULL CHECK (octet_length(kdf_salt) = 16),
  wrapped_account_key_ciphertext bytea NOT NULL CHECK (octet_length(wrapped_account_key_ciphertext) >= 48),
  wrapped_account_key_nonce bytea NOT NULL CHECK (octet_length(wrapped_account_key_nonce) = 24),
  public_encryption_key bytea NOT NULL CHECK (octet_length(public_encryption_key) = 32),
  public_signing_key bytea NOT NULL CHECK (octet_length(public_signing_key) = 32),
  signing_key_fingerprint text NOT NULL,
  candidate_device_id uuid NOT NULL,
  candidate_device_type text NOT NULL CHECK (candidate_device_type IN ('web', 'extension', 'desktop', 'mobile')),
  candidate_device_encryption_public_key bytea NOT NULL
    CHECK (octet_length(candidate_device_encryption_public_key) = 32),
  candidate_device_signing_public_key bytea NOT NULL
    CHECK (octet_length(candidate_device_signing_public_key) = 32),
  candidate_device_key_fingerprint text NOT NULL,
  candidate_device_encrypted_label bytea,
  candidate_device_label_nonce bytea,
  candidate_device_certificate_payload bytea NOT NULL,
  candidate_device_certificate_signature bytea NOT NULL
    CHECK (octet_length(candidate_device_certificate_signature) = 64),
  candidate_user_proof bytea NOT NULL CHECK (octet_length(candidate_user_proof) = 64),
  request_digest bytea NOT NULL UNIQUE CHECK (octet_length(request_digest) = 32),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'approved', 'activated', 'cancelled', 'failed')),
  created_by_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  approved_at timestamptz,
  activated_at timestamptz,
  cancelled_at timestamptz,
  failed_at timestamptz,
  last_error_code text,
  CHECK (created_by_user_id = target_user_id),
  CHECK (expires_at > created_at),
  CHECK (
    (candidate_device_encrypted_label IS NULL AND candidate_device_label_nonce IS NULL)
    OR (candidate_device_encrypted_label IS NOT NULL AND candidate_device_label_nonce IS NOT NULL
      AND octet_length(candidate_device_label_nonce) = 24)
  )
);

CREATE UNIQUE INDEX account_crypto_reset_requests_active_uq
  ON account_crypto_reset_requests (target_user_id)
  WHERE status IN ('pending', 'approved');
CREATE INDEX account_crypto_reset_requests_admin_idx
  ON account_crypto_reset_requests (status, expires_at, created_at DESC);
CREATE UNIQUE INDEX account_crypto_reset_requests_candidate_device_uq
  ON account_crypto_reset_requests (candidate_device_id)
  WHERE status IN ('pending', 'approved', 'activated');

CREATE TABLE account_crypto_reset_approvals (
  request_id uuid NOT NULL REFERENCES account_crypto_reset_requests(id) ON DELETE RESTRICT,
  approver_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
  approved_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (request_id, approver_user_id)
);

CREATE TABLE account_crypto_reset_vaults (
  request_id uuid NOT NULL REFERENCES account_crypto_reset_requests(id) ON DELETE RESTRICT,
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE RESTRICT,
  rekey_job_id uuid REFERENCES vault_rekey_jobs(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (request_id, vault_id)
);
CREATE INDEX account_crypto_reset_vaults_vault_idx
  ON account_crypto_reset_vaults (vault_id, request_id);

CREATE OR REPLACE FUNCTION mima_guard_account_crypto_reset_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  current_profile user_crypto_profiles%ROWTYPE;
BEGIN
  SELECT * INTO current_profile
  FROM user_crypto_profiles
  WHERE user_id = NEW.target_user_id
  FOR UPDATE;
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

CREATE TRIGGER account_crypto_reset_requests_guard_insert
BEFORE INSERT ON account_crypto_reset_requests
FOR EACH ROW EXECUTE FUNCTION mima_guard_account_crypto_reset_insert();

CREATE OR REPLACE FUNCTION mima_guard_account_crypto_reset_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  reset_request account_crypto_reset_requests%ROWTYPE;
BEGIN
  SELECT * INTO reset_request
  FROM account_crypto_reset_requests
  WHERE id = NEW.request_id
  FOR UPDATE;
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
  IF NOT EXISTS (
    SELECT 1 FROM system_role_assignments assignment
    WHERE assignment.user_id = NEW.approver_user_id AND assignment.role = 'platform-admin'
  ) THEN
    RAISE EXCEPTION 'account crypto reset approval requires platform-admin';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER account_crypto_reset_approvals_guard_insert
BEFORE INSERT ON account_crypto_reset_approvals
FOR EACH ROW EXECUTE FUNCTION mima_guard_account_crypto_reset_approval();

CREATE OR REPLACE FUNCTION mima_advance_account_crypto_reset_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF (
    SELECT count(*) FROM account_crypto_reset_approvals approval
    WHERE approval.request_id = NEW.request_id
      AND approval.request_digest = NEW.request_digest
  ) >= 2 THEN
    UPDATE account_crypto_reset_requests
    SET status = 'approved', approved_at = COALESCE(approved_at, now())
    WHERE id = NEW.request_id AND status = 'pending';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER account_crypto_reset_approvals_advance
AFTER INSERT ON account_crypto_reset_approvals
FOR EACH ROW EXECUTE FUNCTION mima_advance_account_crypto_reset_approval();

CREATE OR REPLACE FUNCTION mima_guard_account_crypto_reset_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  approval_count integer;
BEGIN
  IF OLD.status IN ('activated', 'cancelled', 'failed') THEN
    RAISE EXCEPTION 'completed account crypto reset is immutable';
  END IF;
  IF NOT (
    (OLD.status = 'pending' AND NEW.status IN ('pending', 'approved', 'cancelled', 'failed'))
    OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'activated', 'cancelled', 'failed'))
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
  SELECT count(*) INTO approval_count
  FROM account_crypto_reset_approvals approval
  WHERE approval.request_id = OLD.id AND approval.request_digest = OLD.request_digest;
  IF NEW.status IN ('approved', 'activated') AND approval_count < 2 THEN
    RAISE EXCEPTION 'account crypto reset requires two distinct approvals';
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

CREATE TRIGGER account_crypto_reset_requests_guard_update
BEFORE UPDATE ON account_crypto_reset_requests
FOR EACH ROW EXECUTE FUNCTION mima_guard_account_crypto_reset_update();

CREATE OR REPLACE FUNCTION mima_prevent_account_crypto_reset_approval_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'account crypto reset approvals are append-only';
END;
$$;

CREATE TRIGGER account_crypto_reset_approvals_guard_update
BEFORE UPDATE OR DELETE ON account_crypto_reset_approvals
FOR EACH ROW EXECUTE FUNCTION mima_prevent_account_crypto_reset_approval_change();

ALTER TABLE enterprise_recovery_requests
  ADD COLUMN account_reset_request_id uuid
    REFERENCES account_crypto_reset_requests(id) ON DELETE RESTRICT;
ALTER TABLE enterprise_recovery_requests
  ADD CONSTRAINT enterprise_recovery_requests_account_reset_binding_ck
  CHECK (
    (reason = 'account_reset' AND account_reset_request_id IS NOT NULL)
    OR (reason <> 'account_reset' AND account_reset_request_id IS NULL)
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
  IF NEW.reason = 'account_reset' AND NOT EXISTS (
    SELECT 1
    FROM account_crypto_reset_requests reset_request
    JOIN account_crypto_reset_vaults reset_vault
      ON reset_vault.request_id = reset_request.id
    WHERE reset_request.id = NEW.account_reset_request_id
      AND reset_request.target_user_id = NEW.target_user_id
      AND reset_request.candidate_device_id = NEW.target_device_id
      AND reset_request.new_crypto_generation = NEW.target_key_version
      AND reset_request.status = 'activated'
      AND reset_vault.vault_id = NEW.vault_id
  ) THEN
    RAISE EXCEPTION 'enterprise recovery account reset provenance is invalid';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_recovery_account_reset_binding_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.account_reset_request_id IS DISTINCT FROM OLD.account_reset_request_id THEN
    RAISE EXCEPTION 'enterprise recovery account reset binding is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_requests_account_reset_binding_guard_update
BEFORE UPDATE ON enterprise_recovery_requests
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_account_reset_binding_update();
