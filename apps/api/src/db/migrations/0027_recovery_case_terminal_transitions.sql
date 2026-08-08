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
  IF NEW.status NOT IN ('waiting_for_target', 'cancelled', 'expired') AND (
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
