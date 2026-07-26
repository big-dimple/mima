ALTER TABLE users DROP CONSTRAINT IF EXISTS users_source_check;
ALTER TABLE users
  ADD CONSTRAINT users_source_check CHECK (source IN ('dev', 'oidc', 'ldap', 'feishu'));
ALTER TABLE users ADD COLUMN IF NOT EXISTS directory_provider text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS directory_dn text;
ALTER TABLE users ADD COLUMN IF NOT EXISTS directory_stable_id text;
CREATE UNIQUE INDEX IF NOT EXISTS users_directory_identity_uq
  ON users (directory_provider, directory_stable_id)
  WHERE directory_provider IS NOT NULL AND directory_stable_id IS NOT NULL;

DROP INDEX IF EXISTS user_identities_issuer_subject_uq;
CREATE UNIQUE INDEX IF NOT EXISTS user_identities_provider_issuer_subject_uq
  ON user_identities (provider, issuer, subject);

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_auth_method_check;
ALTER TABLE sessions
  ADD CONSTRAINT sessions_auth_method_check CHECK (auth_method IN ('password', 'oidc', 'feishu'));
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_provider text;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS external_namespace text;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS external_subject text;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS external_session_id text;
UPDATE sessions
SET auth_provider = CASE auth_method WHEN 'oidc' THEN 'oidc' ELSE 'dev' END
WHERE auth_provider IS NULL;
ALTER TABLE sessions ALTER COLUMN auth_provider SET NOT NULL;
CREATE INDEX IF NOT EXISTS sessions_external_session_idx
  ON sessions (auth_provider, external_namespace, external_session_id);
CREATE INDEX IF NOT EXISTS sessions_external_subject_idx
  ON sessions (auth_provider, external_namespace, external_subject);

CREATE TABLE IF NOT EXISTS auth_transactions (
  state_hash text PRIMARY KEY,
  provider text NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('login', 'reauth')),
  ciphertext bytea NOT NULL,
  iv bytea NOT NULL,
  auth_tag bytea NOT NULL,
  key_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS auth_transactions_expiry_idx ON auth_transactions (expires_at);

CREATE TABLE IF NOT EXISTS system_role_assignments (
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('platform-admin')),
  assigned_by text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, role)
);

CREATE TABLE IF NOT EXISTS custom_groups (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  owner_user_id text NOT NULL REFERENCES users(id),
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  frozen boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS custom_groups_owner_name_uq
  ON custom_groups (owner_user_id, lower(name));

CREATE TABLE IF NOT EXISTS custom_group_members (
  group_id uuid NOT NULL REFERENCES custom_groups(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  added_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS custom_group_members_user_idx ON custom_group_members (user_id);

CREATE TABLE IF NOT EXISTS vault_custom_group_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  group_id uuid NOT NULL REFERENCES custom_groups(id) ON DELETE RESTRICT,
  role text NOT NULL CHECK (role IN ('viewer', 'editor', 'auditor')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, group_id)
);
CREATE INDEX IF NOT EXISTS vault_custom_group_roles_group_idx
  ON vault_custom_group_roles (group_id);
