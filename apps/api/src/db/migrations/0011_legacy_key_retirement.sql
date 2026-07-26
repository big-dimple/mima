CREATE TABLE legacy_key_retirement_plans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  deployment_id text NOT NULL UNIQUE
    CHECK (length(deployment_id) BETWEEN 1 AND 128)
    CHECK (deployment_id ~ '^[A-Za-z0-9._:-]+$'),
  status text NOT NULL DEFAULT 'planned'
    CHECK (status IN ('planned', 'approved', 'completed', 'not_applicable')),
  reason_code text NOT NULL
    CHECK (reason_code IN ('post_cutover', 'rollback_window', 'regulatory_hold', 'fresh_install')),
  retire_by timestamptz,
  copy_inventory_digest bytea NOT NULL CHECK (octet_length(copy_inventory_digest) = 32),
  copy_manifest_digest bytea NOT NULL CHECK (octet_length(copy_manifest_digest) = 32),
  kek_fingerprint_digest bytea CHECK (
    kek_fingerprint_digest IS NULL OR octet_length(kek_fingerprint_digest) = 32
  ),
  plan_digest bytea NOT NULL UNIQUE CHECK (octet_length(plan_digest) = 32),
  completion_evidence_digest bytea CHECK (
    completion_evidence_digest IS NULL OR octet_length(completion_evidence_digest) = 32
  ),
  created_by_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  created_by_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE RESTRICT,
  plan_signature bytea NOT NULL CHECK (octet_length(plan_signature) = 64),
  created_at timestamptz NOT NULL DEFAULT now(),
  approved_at timestamptz,
  completed_at timestamptz,
  CHECK (
    (reason_code = 'fresh_install' AND retire_by IS NULL AND kek_fingerprint_digest IS NULL)
    OR (
      reason_code <> 'fresh_install'
      AND retire_by IS NOT NULL
      AND retire_by > created_at
      AND kek_fingerprint_digest IS NOT NULL
    )
  ),
  CHECK (
    (status = 'planned' AND approved_at IS NULL AND completed_at IS NULL AND completion_evidence_digest IS NULL)
    OR (status = 'approved' AND approved_at IS NOT NULL AND completed_at IS NULL AND completion_evidence_digest IS NULL)
    OR (
      status IN ('completed', 'not_applicable')
      AND approved_at IS NOT NULL
      AND completed_at IS NOT NULL
      AND completion_evidence_digest IS NOT NULL
    )
  )
);
CREATE INDEX legacy_key_retirement_plans_status_idx
  ON legacy_key_retirement_plans (status, retire_by, created_at DESC);

CREATE TABLE legacy_key_retirement_approvals (
  plan_id uuid NOT NULL REFERENCES legacy_key_retirement_plans(id) ON DELETE RESTRICT,
  approver_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  approver_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE RESTRICT,
  plan_digest bytea NOT NULL CHECK (octet_length(plan_digest) = 32),
  evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  approved_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (plan_id, approver_user_id)
);

CREATE UNIQUE INDEX legacy_migration_evidence_retirement_job_uq
  ON legacy_migration_evidence (job_id, evidence_type)
  WHERE evidence_type = 'legacy_key_retirement';

ALTER TABLE legacy_migration_evidence
  ADD COLUMN retirement_manifest_digest bytea;
ALTER TABLE legacy_migration_evidence
  ADD CONSTRAINT legacy_migration_evidence_retirement_manifest_ck CHECK (
    (evidence_type = 'legacy_key_retirement' AND octet_length(retirement_manifest_digest) = 32)
    OR (evidence_type <> 'legacy_key_retirement' AND retirement_manifest_digest IS NULL)
  );

CREATE OR REPLACE FUNCTION mima_is_platform_admin(candidate_user_id text)
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT EXISTS (
    SELECT 1 FROM system_role_assignments assignment
    WHERE assignment.user_id = candidate_user_id AND assignment.role = 'platform-admin'
  );
$$;

CREATE OR REPLACE FUNCTION mima_no_legacy_content_exists()
RETURNS boolean
LANGUAGE sql
STABLE
AS $$
  SELECT NOT EXISTS (
    SELECT 1
    FROM vaults vault
    JOIN vault_crypto_states state ON state.vault_id = vault.id
    WHERE state.storage_mode = 'legacy'
      AND (
        vault.name <> ''
        OR EXISTS (
          SELECT 1 FROM items item
          WHERE item.vault_id = vault.id
            AND (
              item.title <> '' OR item.username IS NOT NULL OR item.origin IS NOT NULL
              OR item.tags <> '[]'::jsonb OR item.favorite OR item.kind <> 'secure_note'
            )
        )
        OR EXISTS (SELECT 1 FROM item_secret_versions version WHERE version.vault_id = vault.id)
      )
  );
$$;

CREATE OR REPLACE FUNCTION mima_guard_legacy_key_retirement_plan_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NOT mima_is_platform_admin(NEW.created_by_user_id) THEN
    RAISE EXCEPTION 'legacy key retirement plan requires platform-admin';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM user_devices device
    WHERE device.id = NEW.created_by_device_id
      AND device.user_id = NEW.created_by_user_id
      AND device.status = 'active'
  ) THEN
    RAISE EXCEPTION 'legacy key retirement plan requires an active admin device';
  END IF;
  IF NEW.reason_code = 'fresh_install' THEN
    IF EXISTS (SELECT 1 FROM legacy_migration_jobs)
      OR NOT mima_no_legacy_content_exists()
    THEN
      RAISE EXCEPTION 'fresh install retirement status is not applicable to legacy data';
    END IF;
  ELSIF NOT EXISTS (SELECT 1 FROM legacy_migration_jobs WHERE state = 'e2ee') THEN
    RAISE EXCEPTION 'legacy key retirement plan requires a completed migration';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER legacy_key_retirement_plans_guard_insert
BEFORE INSERT ON legacy_key_retirement_plans
FOR EACH ROW EXECUTE FUNCTION mima_guard_legacy_key_retirement_plan_insert();

CREATE OR REPLACE FUNCTION mima_guard_legacy_key_retirement_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  retirement_plan legacy_key_retirement_plans%ROWTYPE;
BEGIN
  SELECT * INTO retirement_plan
  FROM legacy_key_retirement_plans
  WHERE id = NEW.plan_id
  FOR UPDATE;
  IF retirement_plan.id IS NULL OR retirement_plan.status NOT IN ('planned', 'approved') THEN
    RAISE EXCEPTION 'legacy key retirement plan is not open for approval';
  END IF;
  IF NEW.plan_digest <> retirement_plan.plan_digest THEN
    RAISE EXCEPTION 'legacy key retirement approval digest does not match';
  END IF;
  IF EXISTS (
    SELECT 1 FROM legacy_key_retirement_approvals approval
    WHERE approval.plan_id = NEW.plan_id
      AND approval.evidence_digest <> NEW.evidence_digest
  ) THEN
    RAISE EXCEPTION 'legacy key retirement approvals must bind the same completion evidence';
  END IF;
  IF NOT mima_is_platform_admin(NEW.approver_user_id) THEN
    RAISE EXCEPTION 'legacy key retirement approval requires platform-admin';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM user_devices device
    WHERE device.id = NEW.approver_device_id
      AND device.user_id = NEW.approver_user_id
      AND device.status = 'active'
  ) THEN
    RAISE EXCEPTION 'legacy key retirement approval requires an active admin device';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER legacy_key_retirement_approvals_guard_insert
BEFORE INSERT ON legacy_key_retirement_approvals
FOR EACH ROW EXECUTE FUNCTION mima_guard_legacy_key_retirement_approval();

CREATE OR REPLACE FUNCTION mima_advance_legacy_key_retirement_approval()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF (
    SELECT count(*) FROM legacy_key_retirement_approvals approval
    WHERE approval.plan_id = NEW.plan_id AND approval.plan_digest = NEW.plan_digest
  ) >= 2 THEN
    UPDATE legacy_key_retirement_plans
    SET status = 'approved', approved_at = COALESCE(approved_at, now())
    WHERE id = NEW.plan_id AND status = 'planned';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER legacy_key_retirement_approvals_advance
AFTER INSERT ON legacy_key_retirement_approvals
FOR EACH ROW EXECUTE FUNCTION mima_advance_legacy_key_retirement_approval();

CREATE OR REPLACE FUNCTION mima_guard_legacy_key_retirement_evidence()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  retirement_plan legacy_key_retirement_plans%ROWTYPE;
BEGIN
  SELECT * INTO retirement_plan
  FROM legacy_key_retirement_plans
  WHERE deployment_id = NEW.subject_id
  FOR UPDATE;
  IF NEW.evidence_type <> 'legacy_key_retirement'
    OR NEW.stage <> 'e2ee'
    OR NEW.subject_kind <> 'deployment'
    OR NEW.record_count <> 1
    OR retirement_plan.id IS NULL
    OR retirement_plan.status <> 'approved'
  THEN
    RAISE EXCEPTION 'invalid legacy key retirement migration evidence';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM legacy_migration_jobs job
    WHERE job.id = NEW.job_id AND job.state = 'e2ee' AND job.completed_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'legacy key retirement evidence requires a completed migration job';
  END IF;
  IF (
    SELECT count(*) FROM legacy_key_retirement_approvals approval
    WHERE approval.plan_id = retirement_plan.id
      AND approval.plan_digest = retirement_plan.plan_digest
      AND approval.evidence_digest = NEW.retirement_manifest_digest
  ) < 2 THEN
    RAISE EXCEPTION 'legacy key retirement evidence lacks matching dual approval';
  END IF;
  IF NEW.signer_device_id IS NULL OR NEW.signature IS NULL OR NOT EXISTS (
    SELECT 1 FROM user_devices device
    WHERE device.id = NEW.signer_device_id
      AND device.status = 'active'
      AND mima_is_platform_admin(device.user_id)
  ) THEN
    RAISE EXCEPTION 'legacy key retirement evidence requires an active admin device signature';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER legacy_migration_retirement_evidence_guard_insert
BEFORE INSERT ON legacy_migration_evidence
FOR EACH ROW
WHEN (NEW.evidence_type = 'legacy_key_retirement')
EXECUTE FUNCTION mima_guard_legacy_key_retirement_evidence();

CREATE OR REPLACE FUNCTION mima_guard_legacy_key_retirement_plan_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  approval_count integer;
BEGIN
  IF OLD.status IN ('completed', 'not_applicable') THEN
    RAISE EXCEPTION 'completed legacy key retirement plan is immutable';
  END IF;
  IF NOT (
    (OLD.status = 'planned' AND NEW.status IN ('planned', 'approved'))
    OR (OLD.status = 'approved' AND NEW.status IN ('approved', 'completed', 'not_applicable'))
  ) THEN
    RAISE EXCEPTION 'invalid legacy key retirement transition: % -> %', OLD.status, NEW.status;
  END IF;
  IF ROW(
    NEW.id, NEW.deployment_id, NEW.reason_code, NEW.retire_by,
    NEW.copy_inventory_digest, NEW.copy_manifest_digest, NEW.kek_fingerprint_digest,
    NEW.plan_digest, NEW.created_by_user_id, NEW.created_by_device_id,
    NEW.plan_signature, NEW.created_at
  ) IS DISTINCT FROM ROW(
    OLD.id, OLD.deployment_id, OLD.reason_code, OLD.retire_by,
    OLD.copy_inventory_digest, OLD.copy_manifest_digest, OLD.kek_fingerprint_digest,
    OLD.plan_digest, OLD.created_by_user_id, OLD.created_by_device_id,
    OLD.plan_signature, OLD.created_at
  ) THEN
    RAISE EXCEPTION 'legacy key retirement plan binding is immutable';
  END IF;
  SELECT count(*) INTO approval_count
  FROM legacy_key_retirement_approvals approval
  WHERE approval.plan_id = OLD.id AND approval.plan_digest = OLD.plan_digest;
  IF NEW.status IN ('approved', 'completed', 'not_applicable') AND approval_count < 2 THEN
    RAISE EXCEPTION 'legacy key retirement requires two distinct approvals';
  END IF;
  IF NEW.status IN ('planned', 'approved') AND NEW.completion_evidence_digest IS NOT NULL THEN
    RAISE EXCEPTION 'legacy key retirement completion evidence cannot be recorded early';
  END IF;
  IF NEW.status IN ('completed', 'not_applicable') AND (
    NEW.completion_evidence_digest IS NULL
    OR EXISTS (
      SELECT 1 FROM legacy_key_retirement_approvals approval
      WHERE approval.plan_id = OLD.id
        AND (
          approval.plan_digest <> OLD.plan_digest
          OR approval.evidence_digest <> NEW.completion_evidence_digest
        )
    )
  ) THEN
    RAISE EXCEPTION 'legacy key retirement completion evidence lacks matching dual approval';
  END IF;
  IF NEW.status = 'completed' THEN
    IF NEW.reason_code = 'fresh_install'
      OR EXISTS (SELECT 1 FROM vault_crypto_states WHERE storage_mode <> 'e2ee')
      OR EXISTS (
        SELECT 1 FROM legacy_migration_jobs
        WHERE state IN ('preparing', 'frozen', 'encrypting', 'verifying', 'cutover')
      )
      OR NOT EXISTS (SELECT 1 FROM legacy_migration_jobs WHERE state = 'e2ee')
      OR EXISTS (
        SELECT 1 FROM legacy_migration_jobs job
        WHERE job.state = 'e2ee' AND NOT EXISTS (
          SELECT 1 FROM legacy_migration_evidence evidence
          WHERE evidence.job_id = job.id
            AND evidence.evidence_type = 'legacy_key_retirement'
            AND evidence.stage = 'e2ee'
            AND evidence.subject_kind = 'deployment'
            AND evidence.subject_id = NEW.deployment_id
            AND evidence.retirement_manifest_digest = NEW.completion_evidence_digest
        )
      )
    THEN
      RAISE EXCEPTION 'legacy key retirement completion gates are not satisfied';
    END IF;
  END IF;
  IF NEW.status = 'not_applicable' THEN
    IF NEW.reason_code <> 'fresh_install'
      OR EXISTS (SELECT 1 FROM legacy_migration_jobs)
      OR NOT mima_no_legacy_content_exists()
    THEN
      RAISE EXCEPTION 'legacy key retirement is not applicable only to fresh installs';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER legacy_key_retirement_plans_guard_update
BEFORE UPDATE ON legacy_key_retirement_plans
FOR EACH ROW EXECUTE FUNCTION mima_guard_legacy_key_retirement_plan_update();

CREATE OR REPLACE FUNCTION mima_reject_legacy_key_retirement_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'legacy key retirement evidence is append-only';
END;
$$;
CREATE TRIGGER legacy_key_retirement_approvals_guard_mutation
BEFORE UPDATE OR DELETE ON legacy_key_retirement_approvals
FOR EACH ROW EXECUTE FUNCTION mima_reject_legacy_key_retirement_mutation();
CREATE TRIGGER legacy_migration_retirement_evidence_guard_mutation
BEFORE UPDATE OR DELETE ON legacy_migration_evidence
FOR EACH ROW
WHEN (OLD.evidence_type = 'legacy_key_retirement')
EXECUTE FUNCTION mima_reject_legacy_key_retirement_mutation();
