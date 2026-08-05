CREATE TABLE enterprise_recovery_cases (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('forgot_password', 'interrupted_handoff')),
  target_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  recovery_key_id uuid NOT NULL REFERENCES enterprise_recovery_keys(id) ON DELETE RESTRICT,
  status text NOT NULL DEFAULT 'waiting_for_target'
    CHECK (status IN (
      'waiting_for_target',
      'pending_approval',
      'approved',
      'processing',
      'completed',
      'completed_with_skips',
      'cancelled',
      'expired'
    )),
  case_digest bytea,
  target_device_id uuid,
  target_encryption_public_key bytea,
  target_key_version integer,
  account_reset_request_id uuid REFERENCES account_crypto_reset_requests(id) ON DELETE RESTRICT,
  created_by_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  finalized_at timestamptz,
  approved_at timestamptz,
  processing_at timestamptz,
  completed_at timestamptz,
  cancelled_at timestamptz,
  expired_at timestamptz,
  last_error_code text,
  CONSTRAINT enterprise_recovery_cases_digest_ck
    CHECK (case_digest IS NULL OR octet_length(case_digest) = 32),
  CONSTRAINT enterprise_recovery_cases_target_ck CHECK (
    (target_device_id IS NULL AND target_encryption_public_key IS NULL AND target_key_version IS NULL)
    OR (
      target_device_id IS NOT NULL
      AND octet_length(target_encryption_public_key) = 32
      AND target_key_version > 0
    )
  ),
  CONSTRAINT enterprise_recovery_cases_reset_kind_ck CHECK (
    (kind = 'forgot_password' AND (account_reset_request_id IS NULL OR target_device_id IS NOT NULL))
    OR (kind = 'interrupted_handoff' AND account_reset_request_id IS NULL)
  )
);

CREATE UNIQUE INDEX enterprise_recovery_cases_active_target_uq
  ON enterprise_recovery_cases (target_user_id)
  WHERE status IN ('waiting_for_target', 'pending_approval', 'approved', 'processing');
CREATE INDEX enterprise_recovery_cases_admin_idx
  ON enterprise_recovery_cases (status, expires_at, created_at);

CREATE TABLE enterprise_recovery_case_approvals (
  case_id uuid NOT NULL REFERENCES enterprise_recovery_cases(id) ON DELETE RESTRICT,
  approver_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  case_digest bytea NOT NULL CHECK (octet_length(case_digest) = 32),
  approved_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (case_id, approver_user_id)
);

CREATE TABLE enterprise_recovery_case_transfers (
  case_id uuid PRIMARY KEY REFERENCES enterprise_recovery_cases(id) ON DELETE RESTRICT,
  case_digest bytea NOT NULL CHECK (octet_length(case_digest) = 32),
  transfer_digest bytea NOT NULL CHECK (octet_length(transfer_digest) = 32),
  transfer_payload jsonb NOT NULL,
  uploaded_by_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  uploaded_at timestamptz NOT NULL DEFAULT now(),
  consumed_at timestamptz
);

ALTER TABLE account_crypto_reset_requests
  ADD COLUMN case_id uuid REFERENCES enterprise_recovery_cases(id) ON DELETE RESTRICT;
ALTER TABLE account_crypto_reset_requests
  ADD COLUMN recovery_activation_idempotency_key text,
  ADD COLUMN recovery_activation_device_signature bytea,
  ADD COLUMN recovery_activation_user_signature bytea,
  ADD CONSTRAINT account_crypto_reset_requests_recovery_activation_ck CHECK (
    (
      case_id IS NULL
      AND recovery_activation_idempotency_key IS NULL
      AND recovery_activation_device_signature IS NULL
      AND recovery_activation_user_signature IS NULL
    ) OR (
      case_id IS NOT NULL
      AND length(recovery_activation_idempotency_key) BETWEEN 8 AND 80
      AND octet_length(recovery_activation_device_signature) = 64
      AND octet_length(recovery_activation_user_signature) = 64
    )
  );
CREATE UNIQUE INDEX account_crypto_reset_requests_case_uq
  ON account_crypto_reset_requests (case_id)
  WHERE case_id IS NOT NULL;

ALTER TABLE enterprise_recovery_requests
  ADD COLUMN case_id uuid REFERENCES enterprise_recovery_cases(id) ON DELETE RESTRICT;
ALTER TABLE enterprise_recovery_requests
  DROP CONSTRAINT IF EXISTS enterprise_recovery_requests_target_device_id_target_user__fkey;
ALTER TABLE enterprise_recovery_requests
  ADD COLUMN target_key_fingerprint text
    CHECK (target_key_fingerprint IS NULL OR target_key_fingerprint ~ '^[A-Za-z0-9_-]{43}$');
ALTER TABLE enterprise_recovery_requests
  DROP CONSTRAINT enterprise_recovery_requests_status_check,
  ADD CONSTRAINT enterprise_recovery_requests_status_check
    CHECK (status IN ('pending', 'approved', 'satisfied', 'completed', 'cancelled', 'expired', 'failed'));
CREATE INDEX enterprise_recovery_requests_case_idx
  ON enterprise_recovery_requests (case_id, status, vault_id)
  WHERE case_id IS NOT NULL;

CREATE OR REPLACE FUNCTION mima_guard_recovery_case_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  recovery_case enterprise_recovery_cases%ROWTYPE;
  approval_count integer;
BEGIN
  SELECT * INTO recovery_case FROM enterprise_recovery_cases
  WHERE id = NEW.case_id FOR UPDATE;
  IF recovery_case.id IS NULL
    OR recovery_case.status NOT IN ('pending_approval', 'approved')
    OR recovery_case.expires_at <= now()
    OR recovery_case.case_digest IS NULL
  THEN
    RAISE EXCEPTION 'enterprise recovery case is not open for approval';
  END IF;
  IF NEW.case_digest <> recovery_case.case_digest THEN
    RAISE EXCEPTION 'enterprise recovery case approval digest does not match';
  END IF;
  IF NEW.approver_user_id = recovery_case.target_user_id THEN
    RAISE EXCEPTION 'enterprise recovery target cannot approve their own case';
  END IF;
  IF NOT mima_is_platform_admin(NEW.approver_user_id) THEN
    RAISE EXCEPTION 'enterprise recovery case approval requires platform-admin';
  END IF;
  SELECT count(*) INTO approval_count FROM enterprise_recovery_case_approvals
  WHERE case_id = NEW.case_id;
  IF approval_count >= 2 THEN
    RAISE EXCEPTION 'enterprise recovery case already has two approvals';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_case_approvals_guard_insert
BEFORE INSERT ON enterprise_recovery_case_approvals
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_case_approval();

CREATE OR REPLACE FUNCTION mima_advance_recovery_case_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF (
    SELECT count(*) FROM enterprise_recovery_case_approvals approval
    WHERE approval.case_id = NEW.case_id
  ) = 2 THEN
    UPDATE enterprise_recovery_cases
    SET status = 'approved', approved_at = COALESCE(approved_at, now())
    WHERE id = NEW.case_id AND status = 'pending_approval';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_case_approvals_advance
AFTER INSERT ON enterprise_recovery_case_approvals
FOR EACH ROW EXECUTE FUNCTION mima_advance_recovery_case_approval();

CREATE OR REPLACE FUNCTION mima_guard_recovery_case_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  approval_count integer;
BEGIN
  IF OLD.status IN ('completed', 'completed_with_skips', 'cancelled', 'expired') THEN
    RAISE EXCEPTION 'completed enterprise recovery case is immutable';
  END IF;
  IF NOT (
    (OLD.status = 'waiting_for_target' AND NEW.status IN ('waiting_for_target', 'pending_approval', 'cancelled', 'expired'))
    OR (OLD.status = 'pending_approval' AND NEW.status IN ('pending_approval', 'approved', 'cancelled', 'expired'))
    OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'processing', 'completed', 'completed_with_skips', 'cancelled', 'expired'))
    OR (OLD.status = 'processing' AND NEW.status IN ('processing', 'completed', 'completed_with_skips', 'cancelled', 'expired'))
  ) THEN
    RAISE EXCEPTION 'invalid enterprise recovery case transition: % -> %', OLD.status, NEW.status;
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
    OR NEW.kind IS DISTINCT FROM OLD.kind
    OR NEW.target_user_id IS DISTINCT FROM OLD.target_user_id
    OR NEW.recovery_key_id IS DISTINCT FROM OLD.recovery_key_id
    OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
  THEN
    RAISE EXCEPTION 'enterprise recovery case identity is immutable';
  END IF;
  IF OLD.case_digest IS NOT NULL AND (
    NEW.case_digest IS DISTINCT FROM OLD.case_digest
    OR NEW.target_device_id IS DISTINCT FROM OLD.target_device_id
    OR NEW.target_encryption_public_key IS DISTINCT FROM OLD.target_encryption_public_key
    OR NEW.target_key_version IS DISTINCT FROM OLD.target_key_version
    OR NEW.account_reset_request_id IS DISTINCT FROM OLD.account_reset_request_id
    OR NEW.finalized_at IS DISTINCT FROM OLD.finalized_at
  ) THEN
    RAISE EXCEPTION 'finalized enterprise recovery case binding is immutable';
  END IF;
  IF NEW.status <> 'waiting_for_target' AND (
    NEW.case_digest IS NULL
    OR NEW.target_device_id IS NULL
    OR NEW.target_encryption_public_key IS NULL
    OR NEW.target_key_version IS NULL
    OR NEW.finalized_at IS NULL
  ) THEN
    RAISE EXCEPTION 'enterprise recovery case must be finalized before approval';
  END IF;
  SELECT count(*) INTO approval_count FROM enterprise_recovery_case_approvals
  WHERE case_id = OLD.id AND case_digest = OLD.case_digest;
  IF NEW.status IN ('approved', 'processing', 'completed', 'completed_with_skips')
    AND approval_count <> 2
  THEN
    RAISE EXCEPTION 'enterprise recovery case requires exactly two approvals';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_cases_guard_update
BEFORE UPDATE ON enterprise_recovery_cases
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_case_update();

CREATE OR REPLACE FUNCTION mima_prevent_recovery_case_approval_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'enterprise recovery case approvals are append-only';
END;
$$;

CREATE TRIGGER enterprise_recovery_case_approvals_guard_mutation
BEFORE UPDATE OR DELETE ON enterprise_recovery_case_approvals
FOR EACH ROW EXECUTE FUNCTION mima_prevent_recovery_case_approval_change();

CREATE OR REPLACE FUNCTION mima_guard_recovery_request_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  target_matches boolean;
BEGIN
  UPDATE enterprise_recovery_requests
  SET status = 'expired', expired_at = now(), last_error_code = 'request_expired'
  WHERE vault_id = NEW.vault_id
    AND target_user_id = NEW.target_user_id
    AND status IN ('pending', 'approved')
    AND expires_at <= now();

  SELECT (
    EXISTS (
      SELECT 1 FROM user_devices device
      JOIN user_crypto_profiles profile ON profile.user_id = device.user_id
      WHERE device.id = NEW.target_device_id
        AND device.user_id = NEW.target_user_id
        AND device.status = 'active'
        AND profile.crypto_generation = NEW.target_key_version
        AND profile.public_encryption_key = NEW.target_encryption_public_key
    ) OR EXISTS (
      SELECT 1 FROM account_crypto_reset_requests reset
      JOIN enterprise_recovery_cases recovery_case ON recovery_case.id = NEW.case_id
      WHERE reset.id = NEW.account_reset_request_id
        AND reset.case_id = NEW.case_id
        AND reset.target_user_id = NEW.target_user_id
        AND reset.candidate_device_id = NEW.target_device_id
        AND reset.new_crypto_generation = NEW.target_key_version
        AND reset.public_encryption_key = NEW.target_encryption_public_key
        AND reset.status IN ('pending', 'approved', 'activated')
        AND recovery_case.target_user_id = NEW.target_user_id
        AND recovery_case.status IN ('waiting_for_target', 'pending_approval', 'approved', 'processing')
    )
  ) INTO target_matches;

  IF NOT target_matches THEN
    RAISE EXCEPTION 'recovery target profile or device does not match';
  END IF;
  IF NEW.case_id IS NOT NULL AND NEW.target_key_fingerprint IS NULL THEN
    RAISE EXCEPTION 'case recovery request requires target key fingerprint';
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
  IF recovery_request.case_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM enterprise_recovery_case_approvals approval
    WHERE approval.case_id = recovery_request.case_id
      AND approval.approver_user_id = NEW.approver_user_id
  ) THEN
    RAISE EXCEPTION 'case recovery item approval requires matching case approval';
  END IF;
  SELECT count(*) INTO approval_count FROM enterprise_recovery_approvals
  WHERE request_id = NEW.request_id;
  IF approval_count >= 2 THEN
    RAISE EXCEPTION 'enterprise recovery request already has two approvals';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_current_recovery_capability(
  requested_vault_id uuid,
  requested_user_id text
)
RETURNS text
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
  vault_kind text;
  vault_owner text;
  direct_role text;
  has_full_group_role boolean;
  has_metadata_group_role boolean;
BEGIN
  SELECT kind, owner_user_id INTO vault_kind, vault_owner
  FROM vaults WHERE id = requested_vault_id;
  IF vault_kind IS NULL OR NOT EXISTS (
    SELECT 1 FROM users WHERE id = requested_user_id AND active = true
  ) THEN
    RETURN NULL;
  END IF;
  IF vault_kind = 'personal' THEN
    RETURN CASE WHEN vault_owner = requested_user_id THEN 'full' ELSE NULL END;
  END IF;
  SELECT role INTO direct_role FROM vault_memberships
  WHERE vault_id = requested_vault_id
    AND subject_kind = 'user'
    AND subject_id = requested_user_id
  LIMIT 1;
  IF direct_role IS NOT NULL THEN
    RETURN CASE WHEN direct_role = 'auditor' THEN 'metadata' ELSE 'full' END;
  END IF;
  SELECT
    bool_or(role <> 'auditor'),
    bool_or(role = 'auditor')
  INTO has_full_group_role, has_metadata_group_role
  FROM (
    SELECT group_role.role
    FROM vault_custom_group_roles group_role
    JOIN custom_group_members member ON member.group_id = group_role.group_id
    WHERE group_role.vault_id = requested_vault_id
      AND member.user_id = requested_user_id
    UNION ALL
    SELECT membership.role
    FROM vault_memberships membership
    JOIN users recipient ON recipient.id = requested_user_id
    WHERE membership.vault_id = requested_vault_id
      AND membership.subject_kind = 'group'
      AND membership.subject_id = ANY(recipient.groups)
  ) roles;
  IF has_full_group_role THEN RETURN 'full'; END IF;
  IF has_metadata_group_role THEN RETURN 'metadata'; END IF;
  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_recovery_request_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  approval_count integer;
  current_capability text;
BEGIN
  IF OLD.status IN ('satisfied', 'completed', 'cancelled', 'expired', 'failed') THEN
    RAISE EXCEPTION 'completed enterprise recovery request is immutable';
  END IF;
  IF NOT (
    (OLD.status = 'pending' AND NEW.status IN ('pending', 'approved', 'cancelled', 'expired', 'failed'))
    OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'satisfied', 'completed', 'cancelled', 'expired', 'failed'))
  ) THEN
    RAISE EXCEPTION 'invalid enterprise recovery state transition: % -> %', OLD.status, NEW.status;
  END IF;
  IF NEW.request_digest IS DISTINCT FROM OLD.request_digest
    OR NEW.vault_id IS DISTINCT FROM OLD.vault_id
    OR NEW.key_epoch IS DISTINCT FROM OLD.key_epoch
    OR NEW.recovery_key_id IS DISTINCT FROM OLD.recovery_key_id
    OR NEW.target_user_id IS DISTINCT FROM OLD.target_user_id
    OR NEW.target_device_id IS DISTINCT FROM OLD.target_device_id
    OR NEW.target_encryption_public_key IS DISTINCT FROM OLD.target_encryption_public_key
    OR NEW.target_key_fingerprint IS DISTINCT FROM OLD.target_key_fingerprint
    OR NEW.target_key_version IS DISTINCT FROM OLD.target_key_version
    OR NEW.target_capability IS DISTINCT FROM OLD.target_capability
    OR NEW.reason IS DISTINCT FROM OLD.reason
    OR NEW.account_reset_request_id IS DISTINCT FROM OLD.account_reset_request_id
    OR NEW.case_id IS DISTINCT FROM OLD.case_id
    OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
  THEN
    RAISE EXCEPTION 'enterprise recovery request binding is immutable';
  END IF;
  SELECT count(*) INTO approval_count FROM enterprise_recovery_approvals
  WHERE request_id = OLD.id AND request_digest = OLD.request_digest;
  IF NEW.status IN ('approved', 'satisfied', 'completed') AND approval_count <> 2 THEN
    RAISE EXCEPTION 'enterprise recovery requires exactly two distinct approvals';
  END IF;
  IF NEW.status = 'satisfied' AND NOT EXISTS (
    SELECT 1 FROM vault_key_envelopes envelope
    JOIN user_crypto_profiles profile ON profile.user_id = NEW.target_user_id
    WHERE envelope.vault_id = NEW.vault_id
      AND envelope.key_epoch = NEW.key_epoch
      AND envelope.recipient_kind = 'user'
      AND envelope.recipient_user_id = NEW.target_user_id
      AND envelope.envelope_version = NEW.target_key_version
      AND (
        NEW.target_key_fingerprint IS NULL
        OR envelope.recipient_key_fingerprint = NEW.target_key_fingerprint
      )
      AND envelope.access_scope = NEW.target_capability
      AND envelope.status = 'active'
      AND profile.crypto_generation = NEW.target_key_version
      AND profile.public_encryption_key = NEW.target_encryption_public_key
  ) THEN
    RAISE EXCEPTION 'satisfied recovery request lacks a current owner-delivered envelope';
  END IF;
  IF NEW.status = 'completed' THEN
    IF NEW.expires_at <= now() THEN
      RAISE EXCEPTION 'enterprise recovery request has expired';
    END IF;
    current_capability := mima_current_recovery_capability(NEW.vault_id, NEW.target_user_id);
    IF current_capability IS NULL
      OR (NEW.target_capability = 'full' AND current_capability <> 'full')
      OR NOT EXISTS (
        SELECT 1 FROM vault_key_envelopes envelope
        JOIN user_crypto_profiles profile ON profile.user_id = NEW.target_user_id
        JOIN user_devices device ON device.id = envelope.sender_device_id
        JOIN vault_crypto_states crypto_state ON crypto_state.vault_id = NEW.vault_id
        JOIN enterprise_recovery_keys recovery_key ON recovery_key.id = NEW.recovery_key_id
        WHERE envelope.id = NEW.completed_envelope_id
          AND envelope.vault_id = NEW.vault_id
          AND envelope.key_epoch = NEW.key_epoch
          AND envelope.key_epoch = crypto_state.active_epoch
          AND envelope.recipient_kind = 'user'
          AND envelope.recipient_user_id = NEW.target_user_id
          AND (
            NEW.target_key_fingerprint IS NULL
            OR envelope.recipient_key_fingerprint = NEW.target_key_fingerprint
          )
          AND envelope.envelope_version = NEW.target_key_version
          AND envelope.authorization_kind = 'recovery'
          AND envelope.authorization_ref = NEW.id::text
          AND envelope.access_scope = NEW.target_capability
          AND envelope.status = 'active'
          AND envelope.signer_user_id = NEW.target_user_id
          AND envelope.signer_key_version = NEW.target_key_version
          AND envelope.signer_public_key = profile.public_signing_key
          AND profile.crypto_generation = NEW.target_key_version
          AND profile.public_encryption_key = NEW.target_encryption_public_key
          AND device.user_id = NEW.target_user_id
          AND device.status = 'active'
          AND device.device_generation = NEW.target_key_version
          AND recovery_key.status = 'active'
      )
    THEN
      RAISE EXCEPTION 'completed enterprise recovery envelope does not match current request';
    END IF;
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
    OR (OLD.case_id IS NOT NULL AND NEW.case_id IS DISTINCT FROM OLD.case_id)
    OR (OLD.recovery_activation_idempotency_key IS NOT NULL
      AND NEW.recovery_activation_idempotency_key IS DISTINCT FROM OLD.recovery_activation_idempotency_key)
    OR (OLD.recovery_activation_device_signature IS NOT NULL
      AND NEW.recovery_activation_device_signature IS DISTINCT FROM OLD.recovery_activation_device_signature)
    OR (OLD.recovery_activation_user_signature IS NOT NULL
      AND NEW.recovery_activation_user_signature IS DISTINCT FROM OLD.recovery_activation_user_signature)
    OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
  THEN
    RAISE EXCEPTION 'account crypto reset binding is immutable';
  END IF;
  IF OLD.case_id IS NULL AND NEW.case_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM enterprise_recovery_cases recovery_case
    WHERE recovery_case.id = NEW.case_id
      AND recovery_case.kind = 'forgot_password'
      AND recovery_case.target_user_id = NEW.target_user_id
      AND recovery_case.status = 'waiting_for_target'
  ) THEN
    RAISE EXCEPTION 'account crypto reset case binding is invalid';
  END IF;
  IF OLD.case_id IS NULL AND NEW.case_id IS NOT NULL AND (
    NEW.recovery_activation_idempotency_key IS NULL
    OR NEW.recovery_activation_device_signature IS NULL
    OR NEW.recovery_activation_user_signature IS NULL
  ) THEN
    RAISE EXCEPTION 'account crypto reset case requires automatic activation proof';
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

CREATE OR REPLACE FUNCTION mima_guard_recovery_case_transfer()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  recovery_case enterprise_recovery_cases%ROWTYPE;
BEGIN
  SELECT * INTO recovery_case FROM enterprise_recovery_cases
  WHERE id = NEW.case_id FOR UPDATE;
  IF recovery_case.id IS NULL
    OR recovery_case.status NOT IN ('approved', 'processing')
    OR recovery_case.expires_at <= now()
    OR recovery_case.case_digest <> NEW.case_digest
  THEN
    RAISE EXCEPTION 'enterprise recovery case does not accept an offline result';
  END IF;
  IF NOT mima_is_platform_admin(NEW.uploaded_by_user_id) THEN
    RAISE EXCEPTION 'enterprise recovery result upload requires platform-admin';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_case_transfers_guard_insert
BEFORE INSERT ON enterprise_recovery_case_transfers
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_case_transfer();

CREATE OR REPLACE FUNCTION mima_prevent_recovery_case_transfer_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE'
    OR NEW.case_digest IS DISTINCT FROM OLD.case_digest
    OR NEW.transfer_digest IS DISTINCT FROM OLD.transfer_digest
    OR NEW.transfer_payload IS DISTINCT FROM OLD.transfer_payload
    OR NEW.uploaded_by_user_id IS DISTINCT FROM OLD.uploaded_by_user_id
    OR NEW.uploaded_at IS DISTINCT FROM OLD.uploaded_at
  THEN
    RAISE EXCEPTION 'enterprise recovery case transfer is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_case_transfers_guard_mutation
BEFORE UPDATE OR DELETE ON enterprise_recovery_case_transfers
FOR EACH ROW EXECUTE FUNCTION mima_prevent_recovery_case_transfer_change();
