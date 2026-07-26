ALTER TABLE legacy_migration_jobs
  ADD COLUMN export_recipient_user_id text REFERENCES users(id) ON DELETE RESTRICT,
  ADD COLUMN export_recipient_key_version integer,
  ADD COLUMN export_recipient_key_digest bytea,
  ADD COLUMN export_expires_at timestamptz;

ALTER TABLE legacy_migration_jobs ADD CONSTRAINT legacy_migration_jobs_export_recipient_ck CHECK (
  (
    export_recipient_user_id IS NULL
    AND export_recipient_key_version IS NULL
    AND export_recipient_key_digest IS NULL
    AND export_expires_at IS NULL
  ) OR (
    export_recipient_user_id IS NOT NULL
    AND export_recipient_key_version > 0
    AND octet_length(export_recipient_key_digest) = 32
    AND export_expires_at > created_at
  )
);

CREATE TABLE legacy_migration_exports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id uuid NOT NULL UNIQUE REFERENCES legacy_migration_jobs(id) ON DELETE RESTRICT,
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE RESTRICT,
  recipient_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  recipient_key_version integer NOT NULL CHECK (recipient_key_version > 0),
  recipient_key_digest bytea NOT NULL CHECK (octet_length(recipient_key_digest) = 32),
  source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
  export_format text NOT NULL DEFAULT 'mima-legacy-export-v1'
    CHECK (export_format = 'mima-legacy-export-v1'),
  algorithm text NOT NULL DEFAULT 'x25519-xsalsa20-poly1305-sealed-box'
    CHECK (algorithm = 'x25519-xsalsa20-poly1305-sealed-box'),
  sealed_export bytea NOT NULL CHECK (octet_length(sealed_export) > 48),
  sealed_export_digest bytea NOT NULL CHECK (octet_length(sealed_export_digest) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  claimed_at timestamptz,
  claimed_by_device_id uuid REFERENCES user_devices(id) ON DELETE RESTRICT,
  CHECK (expires_at > created_at),
  CHECK ((claimed_at IS NULL) = (claimed_by_device_id IS NULL)),
  CHECK (claimed_at IS NULL OR (claimed_at >= created_at AND claimed_at < expires_at))
);
CREATE INDEX legacy_migration_exports_available_idx
  ON legacy_migration_exports (recipient_user_id, vault_id, expires_at)
  WHERE claimed_at IS NULL;

CREATE TABLE audit_chain_rewrite_transitions (
  migration_job_id uuid PRIMARY KEY REFERENCES legacy_migration_jobs(id) ON DELETE RESTRICT,
  previous_head_id bigint NOT NULL CHECK (previous_head_id > 0),
  previous_head_hash text NOT NULL CHECK (previous_head_hash ~ '^[0-9a-f]{64}$'),
  rewritten_head_id bigint NOT NULL CHECK (rewritten_head_id > 0),
  rewritten_head_hash text NOT NULL CHECK (rewritten_head_hash ~ '^[0-9a-f]{64}$'),
  transition_digest bytea NOT NULL CHECK (octet_length(transition_digest) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (previous_head_id = rewritten_head_id)
);

CREATE OR REPLACE FUNCTION mima_guard_migration_export_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  migration_job legacy_migration_jobs%ROWTYPE;
  crypto_profile user_crypto_profiles%ROWTYPE;
BEGIN
  SELECT * INTO migration_job FROM legacy_migration_jobs WHERE id = NEW.job_id FOR UPDATE;
  IF NOT FOUND
    OR migration_job.state <> 'frozen'
    OR migration_job.vault_id <> NEW.vault_id
    OR migration_job.source_snapshot_hash IS DISTINCT FROM NEW.source_digest
    OR migration_job.export_recipient_user_id <> NEW.recipient_user_id
    OR migration_job.export_recipient_key_version <> NEW.recipient_key_version
    OR migration_job.export_recipient_key_digest IS DISTINCT FROM NEW.recipient_key_digest
    OR migration_job.export_expires_at IS DISTINCT FROM NEW.expires_at THEN
    RAISE EXCEPTION 'migration export does not match the frozen job';
  END IF;

  SELECT * INTO crypto_profile FROM user_crypto_profiles WHERE user_id = NEW.recipient_user_id;
  IF NOT FOUND
    OR crypto_profile.crypto_generation <> NEW.recipient_key_version THEN
    RAISE EXCEPTION 'migration export recipient key changed after freeze';
  END IF;
  IF now() >= NEW.expires_at THEN
    RAISE EXCEPTION 'migration export already expired';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER legacy_migration_exports_guard_insert
BEFORE INSERT ON legacy_migration_exports
FOR EACH ROW EXECUTE FUNCTION mima_guard_migration_export_insert();

CREATE OR REPLACE FUNCTION mima_guard_migration_export_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'migration exports are immutable';
  END IF;
  IF ROW(
    NEW.id, NEW.job_id, NEW.vault_id, NEW.recipient_user_id,
    NEW.recipient_key_version, NEW.recipient_key_digest, NEW.source_digest,
    NEW.export_format, NEW.algorithm, NEW.sealed_export, NEW.sealed_export_digest,
    NEW.created_at, NEW.expires_at
  ) IS DISTINCT FROM ROW(
    OLD.id, OLD.job_id, OLD.vault_id, OLD.recipient_user_id,
    OLD.recipient_key_version, OLD.recipient_key_digest, OLD.source_digest,
    OLD.export_format, OLD.algorithm, OLD.sealed_export, OLD.sealed_export_digest,
    OLD.created_at, OLD.expires_at
  ) THEN
    RAISE EXCEPTION 'migration export ciphertext and binding are immutable';
  END IF;
  IF OLD.claimed_at IS NOT NULL
    OR NEW.claimed_at IS NULL
    OR NEW.claimed_by_device_id IS NULL
    OR NEW.claimed_at >= OLD.expires_at
    OR NOT EXISTS (
      SELECT 1 FROM user_devices
      WHERE id = NEW.claimed_by_device_id
        AND user_id = OLD.recipient_user_id
        AND status = 'active'
    ) THEN
    RAISE EXCEPTION 'invalid migration export claim';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER legacy_migration_exports_guard_update
BEFORE UPDATE ON legacy_migration_exports
FOR EACH ROW EXECUTE FUNCTION mima_guard_migration_export_mutation();
CREATE TRIGGER legacy_migration_exports_guard_delete
BEFORE DELETE ON legacy_migration_exports
FOR EACH ROW EXECUTE FUNCTION mima_guard_migration_export_mutation();

CREATE OR REPLACE FUNCTION mima_reject_audit_transition_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit chain rewrite transitions are immutable';
END;
$$;
CREATE TRIGGER audit_chain_rewrite_transitions_guard_update
BEFORE UPDATE OR DELETE ON audit_chain_rewrite_transitions
FOR EACH ROW EXECUTE FUNCTION mima_reject_audit_transition_mutation();

CREATE OR REPLACE FUNCTION mima_guard_e2ee_vault_legacy_fields()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  crypto_state vault_crypto_states%ROWTYPE;
BEGIN
  SELECT * INTO crypto_state FROM vault_crypto_states WHERE vault_id = NEW.id;
  IF crypto_state.storage_mode = 'e2ee' AND NEW.name <> '' THEN
    RAISE EXCEPTION 'e2ee vault header must be stored only in encrypted_vault_headers';
  END IF;
  IF crypto_state.storage_mode = 'legacy' AND crypto_state.write_state <> 'open' THEN
    IF TG_OP <> 'UPDATE' THEN
      RAISE EXCEPTION 'legacy vault is frozen for migration';
    END IF;
    IF NEW.name <> ''
      OR NEW.id IS DISTINCT FROM OLD.id
      OR NEW.kind IS DISTINCT FROM OLD.kind
      OR NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id
      OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'legacy vault is frozen for migration';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_e2ee_item_legacy_fields()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  crypto_state vault_crypto_states%ROWTYPE;
BEGIN
  SELECT * INTO crypto_state FROM vault_crypto_states WHERE vault_id = NEW.vault_id;
  IF crypto_state.storage_mode = 'e2ee' AND (
    NEW.title <> ''
    OR NEW.kind <> 'secure_note'
    OR NEW.username IS NOT NULL
    OR NEW.origin IS NOT NULL
    OR NEW.tags <> '[]'::jsonb
    OR NEW.favorite
    OR NEW.sensitivity <> 'medium'
  ) THEN
    RAISE EXCEPTION 'e2ee item metadata must be stored only in encrypted_item_metadata_versions';
  END IF;
  IF crypto_state.storage_mode = 'legacy' AND crypto_state.write_state <> 'open' THEN
    IF TG_OP <> 'UPDATE' THEN
      RAISE EXCEPTION 'legacy item is frozen for migration';
    END IF;
    IF NEW.title <> ''
      OR NEW.kind <> 'secure_note'
      OR NEW.username IS NOT NULL
      OR NEW.origin IS NOT NULL
      OR NEW.tags <> '[]'::jsonb
      OR NEW.favorite
      OR NEW.sensitivity <> 'medium'
      OR NEW.id IS DISTINCT FROM OLD.id
      OR NEW.vault_id IS DISTINCT FROM OLD.vault_id
      OR NEW.version IS DISTINCT FROM OLD.version
      OR NEW.secret_version IS DISTINCT FROM OLD.secret_version
      OR NEW.deleted IS DISTINCT FROM OLD.deleted
      OR NEW.created_at IS DISTINCT FROM OLD.created_at
      OR NEW.updated_at IS DISTINCT FROM OLD.updated_at
      OR NEW.updated_by IS DISTINCT FROM OLD.updated_by THEN
      RAISE EXCEPTION 'legacy item is frozen for migration';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_reject_legacy_secret_write()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  crypto_state vault_crypto_states%ROWTYPE;
BEGIN
  SELECT * INTO crypto_state FROM vault_crypto_states WHERE vault_id = NEW.vault_id;
  IF crypto_state.storage_mode = 'e2ee' THEN
    RAISE EXCEPTION 'legacy secret writes are disabled for e2ee vaults';
  END IF;
  IF crypto_state.write_state <> 'open' THEN
    IF TG_OP <> 'UPDATE' THEN
      RAISE EXCEPTION 'legacy secret history is frozen for migration';
    END IF;
    IF NEW.item_kind <> 'secure_note'
      OR NEW.id IS DISTINCT FROM OLD.id
      OR NEW.item_id IS DISTINCT FROM OLD.item_id
      OR NEW.vault_id IS DISTINCT FROM OLD.vault_id
      OR NEW.secret_version IS DISTINCT FROM OLD.secret_version
      OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext
      OR NEW.iv IS DISTINCT FROM OLD.iv
      OR NEW.auth_tag IS DISTINCT FROM OLD.auth_tag
      OR NEW.wrapped_dek IS DISTINCT FROM OLD.wrapped_dek
      OR NEW.key_version IS DISTINCT FROM OLD.key_version
      OR NEW.created_at IS DISTINCT FROM OLD.created_at
      OR NEW.created_by IS DISTINCT FROM OLD.created_by THEN
      RAISE EXCEPTION 'legacy secret history is frozen for migration';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION mima_guard_frozen_sync_payload()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM vault_crypto_states
    WHERE vault_id = NEW.vault_id AND write_state <> 'open'
  ) AND NEW.payload <> '{}'::jsonb THEN
    RAISE EXCEPTION 'frozen vault sync payload must not contain legacy metadata';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER sync_events_guard_frozen_payload
BEFORE INSERT OR UPDATE ON sync_events
FOR EACH ROW EXECUTE FUNCTION mima_guard_frozen_sync_payload();

CREATE OR REPLACE FUNCTION mima_guard_vault_crypto_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.storage_mode = 'e2ee' THEN
    IF NEW.storage_mode <> 'e2ee'
      OR NEW.active_epoch < OLD.active_epoch
      OR NEW.access_generation < OLD.access_generation
      OR NEW.cutover_at IS DISTINCT FROM OLD.cutover_at
      OR NEW.legacy_read_disabled_at IS DISTINCT FROM OLD.legacy_read_disabled_at THEN
      RAISE EXCEPTION 'e2ee vault state cannot be downgraded';
    END IF;
  END IF;

  IF NEW.storage_mode = 'e2ee' AND NOT EXISTS (
    SELECT 1 FROM vault_key_epochs
    WHERE vault_id = NEW.vault_id AND epoch = NEW.active_epoch AND status = 'active'
  ) THEN
    RAISE EXCEPTION 'e2ee vault active epoch must be active';
  END IF;

  IF OLD.storage_mode = 'legacy' AND NEW.storage_mode = 'e2ee' THEN
    IF EXISTS (SELECT 1 FROM vaults WHERE id = NEW.vault_id AND name <> '')
      OR EXISTS (
        SELECT 1 FROM items WHERE vault_id = NEW.vault_id AND (
          title <> '' OR kind <> 'secure_note' OR username IS NOT NULL OR origin IS NOT NULL
          OR tags <> '[]'::jsonb OR favorite OR sensitivity <> 'medium'
        )
      )
      OR EXISTS (
        SELECT 1 FROM item_secret_versions
        WHERE vault_id = NEW.vault_id AND item_kind <> 'secure_note'
      ) THEN
      RAISE EXCEPTION 'legacy plaintext metadata must be cleared before e2ee cutover';
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM vault_key_envelopes
      WHERE vault_id = NEW.vault_id AND key_epoch = NEW.active_epoch
        AND recipient_kind = 'enterprise_recovery' AND access_scope = 'recovery' AND status = 'active'
    ) THEN
      RAISE EXCEPTION 'enterprise recovery envelope is required before e2ee cutover';
    END IF;

    IF EXISTS (
      SELECT 1 FROM items i WHERE i.vault_id = NEW.vault_id AND NOT EXISTS (
        SELECT 1 FROM encrypted_item_metadata_versions metadata
        WHERE metadata.item_id = i.id AND metadata.record_version = i.version
          AND metadata.key_epoch = NEW.active_epoch
      )
    ) THEN
      RAISE EXCEPTION 'encrypted item metadata coverage is incomplete';
    END IF;

    IF EXISTS (
      SELECT 1 FROM item_secret_versions legacy_secret
      WHERE legacy_secret.vault_id = NEW.vault_id AND NOT EXISTS (
        SELECT 1 FROM encrypted_item_secret_versions encrypted_secret
        JOIN encrypted_item_key_wraps key_wrap
          ON key_wrap.item_id = encrypted_secret.item_id
          AND key_wrap.secret_version = encrypted_secret.secret_version
          AND key_wrap.vault_id = encrypted_secret.vault_id
        WHERE encrypted_secret.legacy_secret_version_id = legacy_secret.id
          AND key_wrap.key_epoch = NEW.active_epoch
      )
    ) THEN
      RAISE EXCEPTION 'encrypted secret history coverage is incomplete';
    END IF;

    IF EXISTS (
      SELECT 1 FROM audit_events
      WHERE vault_id = NEW.vault_id AND details <> '{}'::jsonb
    ) THEN
      RAISE EXCEPTION 'encrypted audit context coverage is incomplete';
    END IF;
    IF EXISTS (
      SELECT 1 FROM sync_events
      WHERE vault_id = NEW.vault_id AND payload <> '{}'::jsonb
    ) THEN
      RAISE EXCEPTION 'legacy sync payloads must be cleared before e2ee cutover';
    END IF;
    IF EXISTS (SELECT 1 FROM command_dedup) THEN
      RAISE EXCEPTION 'legacy command response cache must be cleared before e2ee cutover';
    END IF;
    IF NOT EXISTS (
      SELECT 1 FROM audit_chain_rewrite_transitions transition
      JOIN legacy_migration_jobs job ON job.id = transition.migration_job_id
      WHERE job.vault_id = NEW.vault_id AND job.state = 'cutover'
    ) THEN
      RAISE EXCEPTION 'audit chain rewrite transition evidence is required before e2ee cutover';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
