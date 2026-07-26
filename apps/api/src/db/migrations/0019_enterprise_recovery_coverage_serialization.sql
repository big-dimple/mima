CREATE OR REPLACE FUNCTION mima_lock_enterprise_recovery_coverage()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(
    hashtextextended(current_database() || ':mima:enterprise-recovery-coverage', 0)
  );
  RETURN NEW;
END;
$$;

CREATE TRIGGER enterprise_recovery_keys_coverage_lock_update
BEFORE UPDATE OF status ON enterprise_recovery_keys
FOR EACH ROW
WHEN (OLD.status IS DISTINCT FROM NEW.status AND NEW.status = 'active')
EXECUTE FUNCTION mima_lock_enterprise_recovery_coverage();

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

  SELECT id INTO active_recovery_key_id
  FROM enterprise_recovery_keys
  WHERE status = 'active'
  LIMIT 1;

  IF active_recovery_key_id IS NOT NULL AND (
    NEW.active_epoch IS NULL OR NOT EXISTS (
      SELECT 1
      FROM vault_key_envelopes envelope
      WHERE envelope.vault_id = NEW.vault_id
        AND envelope.key_epoch = NEW.active_epoch
        AND envelope.recipient_kind = 'enterprise_recovery'
        AND envelope.recipient_recovery_key_id = active_recovery_key_id
        AND envelope.access_scope = 'recovery'
        AND envelope.status = 'active'
    )
  ) THEN
    RAISE EXCEPTION 'active enterprise recovery key must cover the e2ee vault epoch';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER vault_crypto_states_active_recovery_guard_insert
BEFORE INSERT ON vault_crypto_states
FOR EACH ROW
WHEN (NEW.storage_mode = 'e2ee')
EXECUTE FUNCTION mima_guard_active_recovery_coverage();

CREATE TRIGGER vault_crypto_states_active_recovery_guard_update
BEFORE UPDATE OF storage_mode, active_epoch ON vault_crypto_states
FOR EACH ROW
WHEN (
  NEW.storage_mode = 'e2ee'
  AND (
    OLD.storage_mode IS DISTINCT FROM NEW.storage_mode
    OR OLD.active_epoch IS DISTINCT FROM NEW.active_epoch
  )
)
EXECUTE FUNCTION mima_guard_active_recovery_coverage();
