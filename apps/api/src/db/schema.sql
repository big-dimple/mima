-- mima schema (idempotent). 秘密仅以密文 (bytea) 存储。
CREATE TABLE IF NOT EXISTS users (
  id text PRIMARY KEY,
  username text UNIQUE NOT NULL,
  display_name text NOT NULL,
  email text NOT NULL,
  groups jsonb NOT NULL DEFAULT '[]',
  source text NOT NULL DEFAULT 'dev' CHECK (source IN ('dev', 'oidc')),
  active boolean NOT NULL DEFAULT true,
  directory_synced_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS source text NOT NULL DEFAULT 'dev';
ALTER TABLE users ADD COLUMN IF NOT EXISTS active boolean NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS directory_synced_at timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

CREATE TABLE IF NOT EXISTS user_identities (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  provider text NOT NULL,
  issuer text NOT NULL,
  subject text NOT NULL,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS user_identities_issuer_subject_uq
  ON user_identities (issuer, subject);
CREATE UNIQUE INDEX IF NOT EXISTS user_identities_provider_user_uq
  ON user_identities (provider, user_id);

CREATE TABLE IF NOT EXISTS directory_groups (
  id text PRIMARY KEY,
  provider text NOT NULL,
  provider_group_id text NOT NULL,
  display_name text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  synced_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS directory_sync_state (
  provider text PRIMARY KEY,
  last_attempt_at timestamptz NOT NULL,
  last_success_at timestamptz,
  last_error text,
  user_count integer NOT NULL DEFAULT 0,
  group_count integer NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS vaults (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind text NOT NULL CHECK (kind IN ('personal', 'team')),
  name text NOT NULL,
  owner_user_id text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS vaults_personal_owner_uq
  ON vaults (owner_user_id) WHERE kind = 'personal';

CREATE TABLE IF NOT EXISTS vault_memberships (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  subject_kind text NOT NULL CHECK (subject_kind IN ('user', 'group')),
  subject_id text NOT NULL,
  role text NOT NULL CHECK (role IN ('viewer', 'editor', 'owner', 'auditor')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS vault_memberships_subject_uq
  ON vault_memberships (vault_id, subject_kind, subject_id);

CREATE TABLE IF NOT EXISTS items (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('login', 'api_token', 'secure_note')),
  title text NOT NULL,
  username text,
  origin text,
  tags jsonb NOT NULL DEFAULT '[]',
  favorite boolean NOT NULL DEFAULT false,
  sensitivity text NOT NULL DEFAULT 'medium' CHECK (sensitivity IN ('low', 'medium', 'high')),
  version integer NOT NULL DEFAULT 1,
  secret_version integer NOT NULL DEFAULT 1,
  deleted boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  updated_by text NOT NULL
);
CREATE INDEX IF NOT EXISTS items_vault_idx ON items (vault_id);
-- 供密文行组合外键引用：条目的 (id, vault_id, kind) 三元组
CREATE UNIQUE INDEX IF NOT EXISTS items_id_vault_kind_uq ON items (id, vault_id, kind);

-- 追加式：秘密版本不可原地覆盖（无 UPDATE 路径，唯一键防重复）。
CREATE TABLE IF NOT EXISTS item_secret_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  item_id uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  vault_id uuid NOT NULL,
  item_kind text NOT NULL,
  secret_version integer NOT NULL,
  ciphertext bytea NOT NULL,
  iv bytea NOT NULL,
  auth_tag bytea NOT NULL,
  wrapped_dek bytea NOT NULL,
  key_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS item_secret_versions_uq
  ON item_secret_versions (item_id, secret_version);
-- AAD 上下文一致性：密文行的 (vault_id, item_kind) 必须与所属条目一致，
-- 数据库层面即拒绝"把密文行改挂到其他库/类型"的移花接木。
DO $$
BEGIN
  ALTER TABLE item_secret_versions
    ADD CONSTRAINT item_secret_versions_ctx_fk
    FOREIGN KEY (item_id, vault_id, item_kind)
    REFERENCES items (id, vault_id, kind)
    ON DELETE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

CREATE TABLE IF NOT EXISTS sync_events (
  id bigserial PRIMARY KEY,
  type text NOT NULL,
  vault_id uuid NOT NULL,
  item_id uuid,
  payload jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS sync_events_vault_idx ON sync_events (vault_id);

CREATE TABLE IF NOT EXISTS audit_events (
  id bigserial PRIMARY KEY,
  ts timestamptz NOT NULL DEFAULT now(),
  actor_user_id text,
  action text NOT NULL,
  vault_id uuid,
  item_id uuid,
  success boolean NOT NULL,
  details jsonb NOT NULL DEFAULT '{}',
  prev_hash text NOT NULL,
  hash text NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text UNIQUE NOT NULL,
  user_id text NOT NULL,
  csrf_token text NOT NULL,
  locked boolean NOT NULL DEFAULT false,
  auth_method text NOT NULL DEFAULT 'password' CHECK (auth_method IN ('password', 'oidc')),
  authenticated_at timestamptz NOT NULL DEFAULT now(),
  oidc_issuer text,
  oidc_subject text,
  oidc_sid text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS auth_method text NOT NULL DEFAULT 'password';
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS authenticated_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS oidc_issuer text;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS oidc_subject text;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS oidc_sid text;
CREATE INDEX IF NOT EXISTS sessions_oidc_sid_idx ON sessions (oidc_issuer, oidc_sid);
CREATE INDEX IF NOT EXISTS sessions_oidc_subject_idx ON sessions (oidc_issuer, oidc_subject);

CREATE TABLE IF NOT EXISTS oidc_transactions (
  state_hash text PRIMARY KEY,
  purpose text NOT NULL CHECK (purpose IN ('login', 'reauth')),
  ciphertext bytea NOT NULL,
  iv bytea NOT NULL,
  auth_tag bytea NOT NULL,
  key_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS oidc_logout_tokens (
  jti_hash text PRIMARY KEY,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS extension_pairing_codes (
  code text PRIMARY KEY,
  user_id text NOT NULL,
  -- 绑定生成配对码的 Web 会话：来源会话被锁定/退出后，配对码不可领取
  session_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);
ALTER TABLE extension_pairing_codes ADD COLUMN IF NOT EXISTS session_id uuid;

CREATE TABLE IF NOT EXISTS extension_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash text UNIQUE NOT NULL,
  user_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS command_dedup (
  idempotency_key text NOT NULL,
  user_id text NOT NULL,
  status_code integer NOT NULL,
  response jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (idempotency_key, user_id)
);
