ALTER TABLE enterprise_recovery_keys
  DROP CONSTRAINT enterprise_recovery_keys_threshold_check,
  DROP CONSTRAINT enterprise_recovery_keys_check,
  ADD CONSTRAINT enterprise_recovery_keys_threshold_check CHECK (threshold = 2),
  ADD CONSTRAINT enterprise_recovery_keys_share_count_check CHECK (share_count BETWEEN 2 AND 6),
  ADD COLUMN custody_mode text NOT NULL DEFAULT 'legacy_offline'
    CHECK (custody_mode IN ('legacy_offline', 'administrator_accounts'));

CREATE TABLE enterprise_recovery_custody_shares (
  recovery_key_id uuid NOT NULL REFERENCES enterprise_recovery_keys(id) ON DELETE RESTRICT,
  administrator_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  administrator_key_version integer NOT NULL CHECK (administrator_key_version > 0),
  administrator_encryption_public_key bytea NOT NULL
    CHECK (octet_length(administrator_encryption_public_key) = 32),
  share_index integer NOT NULL CHECK (share_index BETWEEN 1 AND 6),
  sealed_share_ciphertext bytea NOT NULL
    CHECK (octet_length(sealed_share_ciphertext) BETWEEN 49 AND 20000),
  sealed_share_digest bytea NOT NULL CHECK (octet_length(sealed_share_digest) = 32),
  registered_by_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (recovery_key_id, administrator_user_id),
  UNIQUE (recovery_key_id, share_index)
);

CREATE OR REPLACE FUNCTION mima_guard_recovery_custody_share_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'enterprise recovery custody shares are immutable';
END;
$$;

CREATE TRIGGER enterprise_recovery_custody_shares_immutable
BEFORE UPDATE OR DELETE ON enterprise_recovery_custody_shares
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_custody_share_change();

CREATE OR REPLACE FUNCTION mima_guard_recovery_key_custody_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.custody_mode IS DISTINCT FROM OLD.custody_mode THEN
    RAISE EXCEPTION 'enterprise recovery custody mode is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_keys_custody_immutable
BEFORE UPDATE OF custody_mode ON enterprise_recovery_keys
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_key_custody_update();

ALTER TABLE enterprise_recovery_key_approvals
  ADD COLUMN actor_device_id uuid REFERENCES user_devices(id) ON DELETE RESTRICT,
  ADD COLUMN sealed_share_digest bytea CHECK (
    sealed_share_digest IS NULL OR octet_length(sealed_share_digest) = 32
  ),
  ADD COLUMN approval_signature bytea CHECK (
    approval_signature IS NULL OR octet_length(approval_signature) = 64
  ),
  ADD CONSTRAINT enterprise_recovery_key_approvals_managed_fields_ck CHECK (
    (actor_device_id IS NULL AND sealed_share_digest IS NULL AND approval_signature IS NULL)
    OR (actor_device_id IS NOT NULL AND sealed_share_digest IS NOT NULL AND approval_signature IS NOT NULL)
  );

ALTER TABLE enterprise_recovery_cases
  ADD COLUMN resolution_kind text NOT NULL DEFAULT 'recover_access'
    CHECK (resolution_kind IN ('recover_access', 'replace_empty_personal')),
  ADD COLUMN abandoned_vault_id uuid,
  ADD COLUMN replacement_vault_id uuid,
  ADD COLUMN empty_vault_witness_digest bytea,
  ADD CONSTRAINT enterprise_recovery_cases_empty_resolution_ck CHECK (
    (
      resolution_kind = 'recover_access'
      AND abandoned_vault_id IS NULL
      AND replacement_vault_id IS NULL
      AND empty_vault_witness_digest IS NULL
    ) OR (
      resolution_kind = 'replace_empty_personal'
      AND abandoned_vault_id IS NOT NULL
      AND replacement_vault_id IS NOT NULL
      AND empty_vault_witness_digest IS NOT NULL
      AND octet_length(empty_vault_witness_digest) = 32
    )
  );

ALTER TABLE enterprise_recovery_case_approvals
  ADD COLUMN actor_device_id uuid REFERENCES user_devices(id) ON DELETE RESTRICT,
  ADD COLUMN approval_signature bytea CHECK (
    approval_signature IS NULL OR octet_length(approval_signature) = 64
  ),
  ADD CONSTRAINT enterprise_recovery_case_approvals_managed_fields_ck CHECK (
    (actor_device_id IS NULL AND approval_signature IS NULL)
    OR (actor_device_id IS NOT NULL AND approval_signature IS NOT NULL)
  );

CREATE TABLE enterprise_recovery_case_share_relays (
  case_id uuid NOT NULL REFERENCES enterprise_recovery_cases(id) ON DELETE RESTRICT,
  from_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  to_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  to_key_version integer NOT NULL CHECK (to_key_version > 0),
  sealed_share_ciphertext bytea NOT NULL
    CHECK (octet_length(sealed_share_ciphertext) BETWEEN 49 AND 20000),
  sealed_share_digest bytea NOT NULL CHECK (octet_length(sealed_share_digest) = 32),
  case_digest bytea NOT NULL CHECK (octet_length(case_digest) = 32),
  actor_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE RESTRICT,
  relay_signature bytea NOT NULL CHECK (octet_length(relay_signature) = 64),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  PRIMARY KEY (case_id, from_user_id, to_user_id),
  CHECK (from_user_id <> to_user_id)
);
CREATE INDEX enterprise_recovery_case_share_relays_recipient_idx
  ON enterprise_recovery_case_share_relays (to_user_id, expires_at, consumed_at);

CREATE OR REPLACE FUNCTION mima_guard_recovery_administrator_count()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  administrator_count integer;
BEGIN
  IF TG_OP = 'INSERT' AND NEW.role <> 'platform-admin' THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'DELETE' AND OLD.role <> 'platform-admin' THEN
    RETURN OLD;
  END IF;
  SELECT count(*) INTO administrator_count
  FROM system_role_assignments
  WHERE role = 'platform-admin';
  IF TG_OP = 'INSERT' AND administrator_count >= 6 THEN
    RAISE EXCEPTION 'platform administrator limit is six';
  END IF;
  IF TG_OP = 'DELETE'
    AND administrator_count <= 2
    AND EXISTS (SELECT 1 FROM enterprise_recovery_keys WHERE status = 'active')
  THEN
    RAISE EXCEPTION 'active enterprise recovery requires at least two platform administrators';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER system_role_assignments_recovery_count_guard
BEFORE INSERT OR DELETE ON system_role_assignments
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_administrator_count();

CREATE OR REPLACE FUNCTION mima_guard_managed_recovery_key_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  recovery_key enterprise_recovery_keys%ROWTYPE;
  custody_share enterprise_recovery_custody_shares%ROWTYPE;
BEGIN
  SELECT * INTO recovery_key FROM enterprise_recovery_keys
  WHERE id = NEW.recovery_key_id;
  IF recovery_key.custody_mode = 'administrator_accounts' THEN
    SELECT * INTO custody_share FROM enterprise_recovery_custody_shares
    WHERE recovery_key_id = NEW.recovery_key_id
      AND administrator_user_id = NEW.approver_user_id;
    IF custody_share.recovery_key_id IS NULL
      OR NEW.actor_device_id IS NULL
      OR NEW.approval_signature IS NULL
      OR NEW.sealed_share_digest IS DISTINCT FROM custody_share.sealed_share_digest
      OR NOT EXISTS (
        SELECT 1 FROM user_crypto_profiles profile
        WHERE profile.user_id = NEW.approver_user_id
          AND profile.crypto_generation = custody_share.administrator_key_version
          AND profile.public_encryption_key = custody_share.administrator_encryption_public_key
      )
    THEN
      RAISE EXCEPTION 'managed recovery key approval requires current administrator custody';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_key_approvals_managed_guard
BEFORE INSERT ON enterprise_recovery_key_approvals
FOR EACH ROW EXECUTE FUNCTION mima_guard_managed_recovery_key_approval();

CREATE OR REPLACE FUNCTION mima_guard_managed_recovery_case_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  recovery_case enterprise_recovery_cases%ROWTYPE;
  recovery_key enterprise_recovery_keys%ROWTYPE;
BEGIN
  SELECT * INTO recovery_case FROM enterprise_recovery_cases WHERE id = NEW.case_id;
  SELECT * INTO recovery_key FROM enterprise_recovery_keys WHERE id = recovery_case.recovery_key_id;
  IF recovery_key.custody_mode = 'administrator_accounts' AND (
    NEW.actor_device_id IS NULL
    OR NEW.approval_signature IS NULL
    OR NOT EXISTS (
      SELECT 1
      FROM enterprise_recovery_custody_shares custody
      JOIN user_crypto_profiles profile
        ON profile.user_id = custody.administrator_user_id
       AND profile.crypto_generation = custody.administrator_key_version
       AND profile.public_encryption_key = custody.administrator_encryption_public_key
      WHERE custody.recovery_key_id = recovery_key.id
        AND custody.administrator_user_id = NEW.approver_user_id
    )
  ) THEN
    RAISE EXCEPTION 'managed recovery case approval requires current administrator custody';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_case_approvals_managed_guard
BEFORE INSERT ON enterprise_recovery_case_approvals
FOR EACH ROW EXECUTE FUNCTION mima_guard_managed_recovery_case_approval();

CREATE OR REPLACE FUNCTION mima_guard_recovery_case_resolution_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.case_digest IS NOT NULL AND (
    NEW.resolution_kind IS DISTINCT FROM OLD.resolution_kind
    OR NEW.abandoned_vault_id IS DISTINCT FROM OLD.abandoned_vault_id
    OR NEW.replacement_vault_id IS DISTINCT FROM OLD.replacement_vault_id
    OR NEW.empty_vault_witness_digest IS DISTINCT FROM OLD.empty_vault_witness_digest
  ) THEN
    RAISE EXCEPTION 'finalized enterprise recovery resolution is immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_cases_resolution_guard
BEFORE UPDATE ON enterprise_recovery_cases
FOR EACH ROW EXECUTE FUNCTION mima_guard_recovery_case_resolution_update();
