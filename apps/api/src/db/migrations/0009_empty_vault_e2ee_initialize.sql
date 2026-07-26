CREATE OR REPLACE FUNCTION mima_guard_vault_crypto_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  requires_migration_evidence boolean;
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
    SELECT EXISTS (
      SELECT 1 FROM legacy_migration_jobs
      WHERE vault_id = NEW.vault_id AND state = 'cutover'
    ) INTO requires_migration_evidence;

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

    IF requires_migration_evidence THEN
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
    IF NEW.type <> 'vault.rekey_required'
      OR (NEW.payload - 'pendingEpoch' - 'taskId') <> '{}'::jsonb
      OR jsonb_typeof(NEW.payload -> 'pendingEpoch') <> 'number'
      OR jsonb_typeof(NEW.payload -> 'taskId') <> 'string' THEN
      RAISE EXCEPTION 'frozen vault sync payload must contain only opaque rekey routing fields';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
