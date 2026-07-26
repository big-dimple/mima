CREATE SCHEMA mima_migration;
REVOKE ALL ON SCHEMA mima_migration FROM PUBLIC;

CREATE TABLE mima_migration.job_bindings (
  role_name text PRIMARY KEY CHECK (role_name ~ '^[a-z][a-z0-9_]{2,62}$'),
  job_id uuid NOT NULL UNIQUE REFERENCES public.legacy_migration_jobs(id) ON DELETE RESTRICT,
  vault_id uuid NOT NULL REFERENCES public.vaults(id) ON DELETE RESTRICT,
  recipient_user_id text NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
  source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'revoked')),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK ((state = 'active' AND revoked_at IS NULL) OR (state = 'revoked' AND revoked_at IS NOT NULL))
);
REVOKE ALL ON TABLE mima_migration.job_bindings FROM PUBLIC;

CREATE FUNCTION mima_migration.active_job_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, mima_migration
AS $$
  SELECT binding.job_id
  FROM mima_migration.job_bindings binding
  JOIN public.legacy_migration_jobs job ON job.id = binding.job_id
  WHERE binding.role_name = session_user
    AND binding.state = 'active'
    AND binding.expires_at > statement_timestamp()
    AND job.state IN ('frozen', 'encrypting')
    AND job.vault_id = binding.vault_id
    AND job.export_recipient_user_id = binding.recipient_user_id
    AND job.source_snapshot_hash = binding.source_digest
    AND job.export_expires_at > statement_timestamp()
$$;

CREATE FUNCTION mima_migration.active_vault_id()
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, mima_migration
AS $$
  SELECT binding.vault_id
  FROM mima_migration.job_bindings binding
  WHERE binding.role_name = session_user
    AND binding.job_id = mima_migration.active_job_id()
$$;

CREATE FUNCTION mima_migration.active_recipient_user_id()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, mima_migration
AS $$
  SELECT binding.recipient_user_id
  FROM mima_migration.job_bindings binding
  WHERE binding.role_name = session_user
    AND binding.job_id = mima_migration.active_job_id()
$$;

REVOKE ALL ON FUNCTION mima_migration.active_job_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION mima_migration.active_vault_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION mima_migration.active_recipient_user_id() FROM PUBLIC;

CREATE VIEW mima_migration.legacy_migration_jobs
WITH (security_barrier = true)
AS
SELECT *
FROM public.legacy_migration_jobs
WHERE id = mima_migration.active_job_id()
  AND state IN ('frozen', 'encrypting')
WITH LOCAL CHECK OPTION;

CREATE VIEW mima_migration.legacy_migration_records
WITH (security_barrier = true)
AS
SELECT *
FROM public.legacy_migration_records
WHERE job_id = mima_migration.active_job_id()
WITH LOCAL CHECK OPTION;

CREATE VIEW mima_migration.legacy_migration_exports
WITH (security_barrier = true)
AS
SELECT *
FROM public.legacy_migration_exports
WHERE job_id = mima_migration.active_job_id()
  AND vault_id = mima_migration.active_vault_id()
  AND recipient_user_id = mima_migration.active_recipient_user_id()
WITH LOCAL CHECK OPTION;

CREATE VIEW mima_migration.legacy_migration_evidence
WITH (security_barrier = true)
AS
SELECT *
FROM public.legacy_migration_evidence
WHERE job_id = mima_migration.active_job_id()
  AND evidence_type = 'ciphertext_digest'
  AND stage = 'encrypting'
  AND subject_kind = 'vault'
  AND subject_id = mima_migration.active_vault_id()::text
WITH LOCAL CHECK OPTION;

CREATE VIEW mima_migration.vaults
WITH (security_barrier = true)
AS
SELECT *
FROM public.vaults
WHERE id = mima_migration.active_vault_id()
WITH LOCAL CHECK OPTION;

CREATE VIEW mima_migration.vault_memberships
WITH (security_barrier = true)
AS
SELECT *
FROM public.vault_memberships
WHERE vault_id = mima_migration.active_vault_id()
WITH LOCAL CHECK OPTION;

CREATE VIEW mima_migration.items
WITH (security_barrier = true)
AS
SELECT *
FROM public.items
WHERE vault_id = mima_migration.active_vault_id()
WITH LOCAL CHECK OPTION;

CREATE VIEW mima_migration.item_secret_versions
WITH (security_barrier = true)
AS
SELECT *
FROM public.item_secret_versions
WHERE vault_id = mima_migration.active_vault_id()
WITH LOCAL CHECK OPTION;

CREATE VIEW mima_migration.user_crypto_profiles
WITH (security_barrier = true)
AS
SELECT *
FROM public.user_crypto_profiles
WHERE user_id = mima_migration.active_recipient_user_id()
WITH LOCAL CHECK OPTION;

REVOKE ALL ON ALL TABLES IN SCHEMA mima_migration FROM PUBLIC;
