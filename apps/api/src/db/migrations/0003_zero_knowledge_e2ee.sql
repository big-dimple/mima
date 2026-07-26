CREATE TABLE auth_attempts (
  scope text NOT NULL,
  key_hash text NOT NULL,
  window_started_at timestamptz NOT NULL,
  window_expires_at timestamptz NOT NULL,
  failure_count integer NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
  blocked_until timestamptz,
  last_attempt_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (scope, key_hash),
  CHECK (window_expires_at > window_started_at)
);
CREATE INDEX auth_attempts_cleanup_idx
  ON auth_attempts (window_expires_at, blocked_until);

CREATE UNIQUE INDEX items_id_vault_uq ON items (id, vault_id);
ALTER TABLE item_secret_versions DROP CONSTRAINT IF EXISTS item_secret_versions_ctx_fk;
ALTER TABLE item_secret_versions ADD CONSTRAINT item_secret_versions_ctx_fk
  FOREIGN KEY (item_id, vault_id, item_kind)
  REFERENCES items(id, vault_id, kind)
  ON DELETE CASCADE
  ON UPDATE CASCADE
  DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE enterprise_recovery_keys (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  key_fingerprint text NOT NULL UNIQUE,
  public_encryption_key bytea NOT NULL CHECK (octet_length(public_encryption_key) = 32),
  threshold integer NOT NULL DEFAULT 2 CHECK (threshold >= 2),
  share_count integer NOT NULL DEFAULT 3 CHECK (share_count >= threshold),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired', 'compromised')),
  ceremony_evidence_digest bytea NOT NULL CHECK (octet_length(ceremony_evidence_digest) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  retired_at timestamptz,
  CHECK ((status = 'active' AND retired_at IS NULL) OR status <> 'active')
);
CREATE UNIQUE INDEX enterprise_recovery_keys_active_uq
  ON enterprise_recovery_keys ((status)) WHERE status = 'active';

CREATE TABLE user_crypto_profiles (
  user_id text PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  protocol_version text NOT NULL DEFAULT 'lm-e2ee-v1',
  profile_version integer NOT NULL DEFAULT 1 CHECK (profile_version > 0),
  crypto_generation integer NOT NULL DEFAULT 1 CHECK (crypto_generation > 0),
  kdf_algorithm text NOT NULL DEFAULT 'argon2id13',
  kdf_memory_kib integer NOT NULL DEFAULT 65536,
  kdf_iterations integer NOT NULL DEFAULT 3,
  kdf_parallelism integer NOT NULL DEFAULT 1,
  kdf_salt bytea NOT NULL CHECK (octet_length(kdf_salt) = 16),
  wrapped_account_key_ciphertext bytea NOT NULL CHECK (octet_length(wrapped_account_key_ciphertext) >= 48),
  wrapped_account_key_nonce bytea NOT NULL CHECK (octet_length(wrapped_account_key_nonce) = 24),
  encrypted_private_key_bundle bytea NOT NULL CHECK (octet_length(encrypted_private_key_bundle) > 16),
  private_key_bundle_nonce bytea NOT NULL CHECK (octet_length(private_key_bundle_nonce) = 24),
  public_encryption_key bytea NOT NULL CHECK (octet_length(public_encryption_key) = 32),
  public_signing_key bytea NOT NULL CHECK (octet_length(public_signing_key) = 32),
  signing_key_fingerprint text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (
    protocol_version <> 'lm-e2ee-v1'
    OR (
      kdf_algorithm = 'argon2id13'
      AND kdf_memory_kib = 65536
      AND kdf_iterations = 3
      AND kdf_parallelism = 1
    )
  )
);

CREATE TABLE user_devices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_type text NOT NULL CHECK (device_type IN ('web', 'extension', 'desktop', 'mobile')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked')),
  trust_method text NOT NULL CHECK (trust_method IN ('master_password', 'device_approval', 'passkey_prf', 'recovery')),
  device_generation integer NOT NULL DEFAULT 1 CHECK (device_generation > 0),
  key_fingerprint text NOT NULL,
  public_encryption_key bytea NOT NULL CHECK (octet_length(public_encryption_key) = 32),
  public_signing_key bytea NOT NULL CHECK (octet_length(public_signing_key) = 32),
  encrypted_private_key_bundle bytea NOT NULL CHECK (octet_length(encrypted_private_key_bundle) > 16),
  private_key_bundle_nonce bytea NOT NULL CHECK (octet_length(private_key_bundle_nonce) = 24),
  encrypted_label bytea NOT NULL CHECK (octet_length(encrypted_label) > 16),
  label_nonce bytea NOT NULL CHECK (octet_length(label_nonce) = 24),
  certificate_payload bytea NOT NULL,
  certificate_signature bytea NOT NULL CHECK (octet_length(certificate_signature) = 64),
  approved_by_device_id uuid REFERENCES user_devices(id) ON DELETE SET NULL,
  webauthn_credential_id bytea,
  webauthn_public_key bytea,
  webauthn_prf_salt bytea,
  webauthn_sign_count integer NOT NULL DEFAULT 0 CHECK (webauthn_sign_count >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  last_seen_at timestamptz,
  revoked_at timestamptz,
  revoked_by_user_id text REFERENCES users(id) ON DELETE SET NULL,
  revocation_reason text,
  UNIQUE (user_id, key_fingerprint),
  CHECK ((status <> 'active') OR activated_at IS NOT NULL),
  CHECK ((status <> 'revoked') OR revoked_at IS NOT NULL),
  CHECK (
    (webauthn_credential_id IS NULL AND webauthn_public_key IS NULL AND webauthn_prf_salt IS NULL)
    OR (webauthn_credential_id IS NOT NULL AND webauthn_public_key IS NOT NULL AND webauthn_prf_salt IS NOT NULL)
  )
);
CREATE UNIQUE INDEX user_devices_webauthn_credential_uq
  ON user_devices (webauthn_credential_id) WHERE webauthn_credential_id IS NOT NULL;
CREATE INDEX user_devices_user_status_idx ON user_devices (user_id, status);

ALTER TABLE sessions ADD COLUMN unlock_generation integer NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN unlocked_device_id uuid;
ALTER TABLE sessions ADD COLUMN unlocked_at timestamptz;
ALTER TABLE sessions ADD CONSTRAINT sessions_unlocked_device_fk
  FOREIGN KEY (unlocked_device_id) REFERENCES user_devices(id) ON DELETE SET NULL;

CREATE TABLE session_unlock_challenges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
  purpose text NOT NULL CHECK (purpose IN ('unlock', 'device_activation', 'sensitive_command', 'recovery')),
  challenge_hash bytea NOT NULL UNIQUE CHECK (octet_length(challenge_hash) = 32),
  session_generation integer NOT NULL CHECK (session_generation >= 0),
  profile_version integer NOT NULL CHECK (profile_version > 0),
  device_generation integer NOT NULL CHECK (device_generation > 0),
  failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  verified_at timestamptz,
  consumed_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK (verified_at IS NULL OR consumed_at IS NOT NULL)
);
CREATE INDEX session_unlock_challenges_session_idx
  ON session_unlock_challenges (session_id, expires_at);
CREATE INDEX session_unlock_challenges_cleanup_idx
  ON session_unlock_challenges (expires_at, consumed_at);

CREATE TABLE device_enrollment_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  requested_by_session_id uuid NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  device_type text NOT NULL CHECK (device_type IN ('web', 'extension', 'desktop', 'mobile')),
  requesting_key_fingerprint text NOT NULL,
  requesting_encryption_public_key bytea NOT NULL CHECK (octet_length(requesting_encryption_public_key) = 32),
  requesting_signing_public_key bytea NOT NULL CHECK (octet_length(requesting_signing_public_key) = 32),
  join_channel_public_key bytea NOT NULL CHECK (octet_length(join_channel_public_key) = 32),
  encrypted_label bytea NOT NULL CHECK (octet_length(encrypted_label) > 16),
  label_nonce bytea NOT NULL CHECK (octet_length(label_nonce) = 24),
  challenge_hash bytea NOT NULL UNIQUE CHECK (octet_length(challenge_hash) = 32),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'claimed', 'rejected', 'expired')),
  approved_by_device_id uuid REFERENCES user_devices(id) ON DELETE SET NULL,
  approval_ciphertext bytea,
  approval_nonce bytea,
  approval_signature bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  approved_at timestamptz,
  claimed_at timestamptz,
  CHECK (expires_at > created_at),
  CHECK ((approval_ciphertext IS NULL) = (approval_nonce IS NULL)),
  CHECK (approval_nonce IS NULL OR octet_length(approval_nonce) = 24),
  CHECK (approval_signature IS NULL OR octet_length(approval_signature) = 64),
  CHECK ((status NOT IN ('approved', 'claimed')) OR (approval_ciphertext IS NOT NULL AND approval_signature IS NOT NULL))
);
CREATE INDEX device_enrollment_requests_user_status_idx
  ON device_enrollment_requests (user_id, status, expires_at);

ALTER TABLE extension_pairing_codes ADD COLUMN enrollment_request_id uuid;
ALTER TABLE extension_pairing_codes ADD CONSTRAINT extension_pairing_codes_enrollment_request_fk
  FOREIGN KEY (enrollment_request_id) REFERENCES device_enrollment_requests(id) ON DELETE CASCADE;
ALTER TABLE extension_sessions ADD COLUMN device_id uuid;
ALTER TABLE extension_sessions ADD COLUMN security_generation integer NOT NULL DEFAULT 0;
ALTER TABLE extension_sessions ADD CONSTRAINT extension_sessions_device_fk
  FOREIGN KEY (device_id) REFERENCES user_devices(id) ON DELETE CASCADE;
CREATE INDEX extension_sessions_device_idx ON extension_sessions (device_id);

CREATE TABLE vault_key_epochs (
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  epoch integer NOT NULL CHECK (epoch > 0),
  previous_epoch integer,
  status text NOT NULL DEFAULT 'preparing' CHECK (status IN ('preparing', 'active', 'retired', 'compromised')),
  reason text NOT NULL CHECK (reason IN ('initial', 'migration', 'membership_change', 'device_compromise', 'manual', 'ownership_transfer')),
  metadata_key_commitment bytea NOT NULL CHECK (octet_length(metadata_key_commitment) = 32),
  content_key_commitment bytea NOT NULL CHECK (octet_length(content_key_commitment) = 32),
  recipient_set_digest bytea NOT NULL CHECK (octet_length(recipient_set_digest) = 32),
  created_by_user_id text REFERENCES users(id) ON DELETE SET NULL,
  created_by_device_id uuid REFERENCES user_devices(id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  retired_at timestamptz,
  PRIMARY KEY (vault_id, epoch),
  FOREIGN KEY (vault_id, previous_epoch)
    REFERENCES vault_key_epochs(vault_id, epoch)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK (previous_epoch IS NULL OR previous_epoch < epoch),
  CHECK ((status <> 'active') OR activated_at IS NOT NULL),
  CHECK ((status NOT IN ('retired', 'compromised')) OR retired_at IS NOT NULL)
);
CREATE UNIQUE INDEX vault_key_epochs_active_uq
  ON vault_key_epochs (vault_id) WHERE status = 'active';

CREATE TABLE vault_crypto_states (
  vault_id uuid PRIMARY KEY REFERENCES vaults(id) ON DELETE CASCADE,
  protocol_version text NOT NULL DEFAULT 'lm-e2ee-v1',
  storage_mode text NOT NULL DEFAULT 'legacy' CHECK (storage_mode IN ('legacy', 'e2ee')),
  write_state text NOT NULL DEFAULT 'open' CHECK (write_state IN ('open', 'frozen', 'rekeying')),
  active_epoch integer,
  active_header_version integer NOT NULL DEFAULT 0 CHECK (active_header_version >= 0),
  access_generation integer NOT NULL DEFAULT 0 CHECK (access_generation >= 0),
  row_version integer NOT NULL DEFAULT 1 CHECK (row_version > 0),
  cutover_at timestamptz,
  legacy_read_disabled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (vault_id, active_epoch)
    REFERENCES vault_key_epochs(vault_id, epoch)
    DEFERRABLE INITIALLY DEFERRED,
  CHECK (
    (storage_mode = 'legacy' AND active_epoch IS NULL AND active_header_version = 0 AND cutover_at IS NULL AND legacy_read_disabled_at IS NULL)
    OR
    (storage_mode = 'e2ee' AND active_epoch > 0 AND active_header_version > 0 AND cutover_at IS NOT NULL AND legacy_read_disabled_at IS NOT NULL)
  )
);
CREATE TABLE legacy_migration_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE RESTRICT,
  attempt integer NOT NULL DEFAULT 1 CHECK (attempt > 0),
  state text NOT NULL DEFAULT 'legacy' CHECK (state IN ('legacy', 'preparing', 'frozen', 'encrypting', 'verifying', 'cutover', 'e2ee', 'failed')),
  source_format text NOT NULL DEFAULT 'server-envelope-v1',
  target_protocol text NOT NULL DEFAULT 'lm-e2ee-v1',
  target_epoch integer NOT NULL CHECK (target_epoch > 0),
  source_snapshot_hash bytea CHECK (source_snapshot_hash IS NULL OR octet_length(source_snapshot_hash) = 32),
  source_audit_head_hash text,
  expected_item_count integer NOT NULL DEFAULT 0 CHECK (expected_item_count >= 0),
  expected_metadata_version_count integer NOT NULL DEFAULT 0 CHECK (expected_metadata_version_count >= 0),
  expected_secret_version_count integer NOT NULL DEFAULT 0 CHECK (expected_secret_version_count >= 0),
  expected_recipient_count integer NOT NULL DEFAULT 0 CHECK (expected_recipient_count >= 0),
  expected_audit_event_count integer NOT NULL DEFAULT 0 CHECK (expected_audit_event_count >= 0),
  verified_item_count integer NOT NULL DEFAULT 0 CHECK (verified_item_count >= 0),
  verified_metadata_version_count integer NOT NULL DEFAULT 0 CHECK (verified_metadata_version_count >= 0),
  verified_secret_version_count integer NOT NULL DEFAULT 0 CHECK (verified_secret_version_count >= 0),
  verified_recipient_count integer NOT NULL DEFAULT 0 CHECK (verified_recipient_count >= 0),
  verified_audit_event_count integer NOT NULL DEFAULT 0 CHECK (verified_audit_event_count >= 0),
  started_by_user_id text REFERENCES users(id) ON DELETE SET NULL,
  started_by_device_id uuid REFERENCES user_devices(id) ON DELETE SET NULL,
  last_error_code text,
  last_error_detail_ciphertext bytea,
  last_error_detail_nonce bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  frozen_at timestamptz,
  verified_at timestamptz,
  cutover_at timestamptz,
  completed_at timestamptz,
  rolled_back_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (vault_id, attempt),
  FOREIGN KEY (vault_id, target_epoch) REFERENCES vault_key_epochs(vault_id, epoch),
  CHECK ((last_error_detail_ciphertext IS NULL) = (last_error_detail_nonce IS NULL)),
  CHECK (last_error_detail_nonce IS NULL OR octet_length(last_error_detail_nonce) = 24)
);
CREATE UNIQUE INDEX legacy_migration_jobs_active_uq
  ON legacy_migration_jobs (vault_id)
  WHERE state IN ('preparing', 'frozen', 'encrypting', 'verifying', 'cutover');

CREATE TABLE vault_key_envelopes (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  key_epoch integer NOT NULL CHECK (key_epoch > 0),
  recipient_kind text NOT NULL CHECK (recipient_kind IN ('user', 'device', 'enterprise_recovery')),
  access_scope text NOT NULL CHECK (access_scope IN ('metadata', 'full', 'recovery')),
  recipient_user_id text REFERENCES users(id) ON DELETE CASCADE,
  recipient_device_id uuid REFERENCES user_devices(id) ON DELETE CASCADE,
  recipient_recovery_key_id uuid REFERENCES enterprise_recovery_keys(id) ON DELETE RESTRICT,
  recipient_key_fingerprint text NOT NULL,
  authorization_kind text NOT NULL CHECK (authorization_kind IN ('direct', 'custom_group', 'directory_group', 'owner', 'recovery', 'migration')),
  authorization_ref text,
  algorithm text NOT NULL DEFAULT 'x25519-sealed-box',
  envelope_version integer NOT NULL DEFAULT 1 CHECK (envelope_version > 0),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 48),
  ciphertext_digest bytea NOT NULL CHECK (octet_length(ciphertext_digest) = 32),
  sender_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE RESTRICT,
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'revoked', 'superseded')),
  created_at timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  revoked_at timestamptz,
  revocation_reason text,
  FOREIGN KEY (vault_id, key_epoch) REFERENCES vault_key_epochs(vault_id, epoch) ON DELETE CASCADE,
  UNIQUE (vault_id, key_epoch, recipient_kind, recipient_key_fingerprint, access_scope),
  CHECK (
    (recipient_kind = 'user' AND recipient_user_id IS NOT NULL AND recipient_device_id IS NULL AND recipient_recovery_key_id IS NULL AND access_scope IN ('metadata', 'full'))
    OR
    (recipient_kind = 'device' AND recipient_user_id IS NULL AND recipient_device_id IS NOT NULL AND recipient_recovery_key_id IS NULL AND access_scope IN ('metadata', 'full'))
    OR
    (recipient_kind = 'enterprise_recovery' AND recipient_user_id IS NULL AND recipient_device_id IS NULL AND recipient_recovery_key_id IS NOT NULL AND access_scope = 'recovery')
  ),
  CHECK ((status <> 'active') OR activated_at IS NOT NULL),
  CHECK ((status NOT IN ('revoked', 'superseded')) OR revoked_at IS NOT NULL)
);
CREATE INDEX vault_key_envelopes_recipient_user_idx
  ON vault_key_envelopes (recipient_user_id, status, vault_id) WHERE recipient_user_id IS NOT NULL;
CREATE INDEX vault_key_envelopes_recipient_device_idx
  ON vault_key_envelopes (recipient_device_id, status, vault_id) WHERE recipient_device_id IS NOT NULL;
CREATE INDEX vault_key_envelopes_epoch_idx
  ON vault_key_envelopes (vault_id, key_epoch, status);

CREATE TABLE encrypted_vault_headers (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  header_version integer NOT NULL CHECK (header_version > 0),
  key_epoch integer NOT NULL CHECK (key_epoch > 0),
  protocol_version text NOT NULL DEFAULT 'lm-e2ee-v1',
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 16),
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 24),
  ciphertext_digest bytea NOT NULL CHECK (octet_length(ciphertext_digest) = 32),
  created_by_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE RESTRICT,
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  migration_job_id uuid REFERENCES legacy_migration_jobs(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (vault_id, key_epoch) REFERENCES vault_key_epochs(vault_id, epoch) ON DELETE CASCADE,
  UNIQUE (vault_id, header_version, key_epoch)
);
CREATE INDEX encrypted_vault_headers_current_idx
  ON encrypted_vault_headers (vault_id, key_epoch, header_version DESC);
ALTER TABLE vault_crypto_states ADD CONSTRAINT vault_crypto_states_active_header_fk
  FOREIGN KEY (vault_id, active_header_version, active_epoch)
  REFERENCES encrypted_vault_headers(vault_id, header_version, key_epoch)
  DEFERRABLE INITIALLY DEFERRED;

-- Backfill only after every constraint on vault_crypto_states exists. PostgreSQL
-- otherwise refuses the later ALTER TABLE while INSERT trigger events are pending.
INSERT INTO vault_crypto_states (vault_id)
SELECT id FROM vaults
ON CONFLICT (vault_id) DO NOTHING;

CREATE TABLE encrypted_item_metadata_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  item_id uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  vault_id uuid NOT NULL,
  record_version integer NOT NULL CHECK (record_version > 0),
  key_epoch integer NOT NULL CHECK (key_epoch > 0),
  protocol_version text NOT NULL DEFAULT 'lm-e2ee-v1',
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 16),
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 24),
  ciphertext_digest bytea NOT NULL CHECK (octet_length(ciphertext_digest) = 32),
  created_by_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE RESTRICT,
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  migration_job_id uuid REFERENCES legacy_migration_jobs(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (item_id, vault_id)
    REFERENCES items(id, vault_id) ON DELETE CASCADE,
  FOREIGN KEY (vault_id, key_epoch)
    REFERENCES vault_key_epochs(vault_id, epoch) ON DELETE CASCADE,
  UNIQUE (item_id, record_version, key_epoch)
);
CREATE INDEX encrypted_item_metadata_versions_vault_idx
  ON encrypted_item_metadata_versions (vault_id, key_epoch, item_id, record_version DESC);

CREATE TABLE encrypted_item_secret_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  item_id uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
  vault_id uuid NOT NULL,
  record_version integer NOT NULL CHECK (record_version > 0),
  secret_version integer NOT NULL CHECK (secret_version > 0),
  protocol_version text NOT NULL DEFAULT 'lm-e2ee-v1',
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) > 16),
  nonce bytea NOT NULL CHECK (octet_length(nonce) = 24),
  ciphertext_digest bytea NOT NULL CHECK (octet_length(ciphertext_digest) = 32),
  created_by_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE RESTRICT,
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  legacy_secret_version_id uuid REFERENCES item_secret_versions(id) ON DELETE RESTRICT,
  migration_job_id uuid REFERENCES legacy_migration_jobs(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (item_id, vault_id)
    REFERENCES items(id, vault_id) ON DELETE CASCADE,
  UNIQUE (item_id, secret_version),
  UNIQUE (item_id, secret_version, vault_id),
  UNIQUE (legacy_secret_version_id),
  CHECK (secret_version <= record_version)
);
CREATE INDEX encrypted_item_secret_versions_vault_idx
  ON encrypted_item_secret_versions (vault_id, item_id, secret_version DESC);

CREATE TABLE encrypted_item_key_wraps (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  item_id uuid NOT NULL,
  secret_version integer NOT NULL CHECK (secret_version > 0),
  vault_id uuid NOT NULL,
  key_epoch integer NOT NULL CHECK (key_epoch > 0),
  wrapped_dek_ciphertext bytea NOT NULL CHECK (octet_length(wrapped_dek_ciphertext) >= 48),
  wrapped_dek_nonce bytea NOT NULL CHECK (octet_length(wrapped_dek_nonce) = 24),
  ciphertext_digest bytea NOT NULL CHECK (octet_length(ciphertext_digest) = 32),
  created_by_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE RESTRICT,
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  migration_job_id uuid REFERENCES legacy_migration_jobs(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (item_id, secret_version, vault_id)
    REFERENCES encrypted_item_secret_versions(item_id, secret_version, vault_id) ON DELETE CASCADE,
  FOREIGN KEY (vault_id, key_epoch)
    REFERENCES vault_key_epochs(vault_id, epoch) ON DELETE CASCADE,
  UNIQUE (item_id, secret_version, key_epoch)
);
CREATE INDEX encrypted_item_key_wraps_epoch_idx
  ON encrypted_item_key_wraps (vault_id, key_epoch, item_id);

CREATE TABLE vault_rekey_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE RESTRICT,
  from_epoch integer NOT NULL CHECK (from_epoch > 0),
  to_epoch integer NOT NULL CHECK (to_epoch > 0),
  reason text NOT NULL CHECK (reason IN ('membership_change', 'device_compromise', 'manual', 'ownership_transfer')),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'distributing', 'rewrapping', 'verifying', 'ready', 'committed', 'failed', 'cancelled')),
  freeze_generation integer NOT NULL CHECK (freeze_generation >= 0),
  expected_recipient_count integer NOT NULL DEFAULT 0 CHECK (expected_recipient_count >= 0),
  distributed_recipient_count integer NOT NULL DEFAULT 0 CHECK (distributed_recipient_count >= 0),
  expected_secret_version_count integer NOT NULL DEFAULT 0 CHECK (expected_secret_version_count >= 0),
  rewrapped_secret_version_count integer NOT NULL DEFAULT 0 CHECK (rewrapped_secret_version_count >= 0),
  expected_metadata_version_count integer NOT NULL DEFAULT 0 CHECK (expected_metadata_version_count >= 0),
  reencrypted_metadata_version_count integer NOT NULL DEFAULT 0 CHECK (reencrypted_metadata_version_count >= 0),
  checkpoint_cursor text,
  source_digest bytea CHECK (source_digest IS NULL OR octet_length(source_digest) = 32),
  result_digest bytea CHECK (result_digest IS NULL OR octet_length(result_digest) = 32),
  verification_signature bytea CHECK (verification_signature IS NULL OR octet_length(verification_signature) = 64),
  initiated_by_user_id text REFERENCES users(id) ON DELETE SET NULL,
  initiated_by_device_id uuid REFERENCES user_devices(id) ON DELETE SET NULL,
  last_error_code text,
  last_error_detail_ciphertext bytea,
  last_error_detail_nonce bytea,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  committed_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (vault_id, from_epoch) REFERENCES vault_key_epochs(vault_id, epoch),
  FOREIGN KEY (vault_id, to_epoch) REFERENCES vault_key_epochs(vault_id, epoch),
  UNIQUE (vault_id, to_epoch),
  CHECK (to_epoch > from_epoch),
  CHECK ((last_error_detail_ciphertext IS NULL) = (last_error_detail_nonce IS NULL)),
  CHECK (last_error_detail_nonce IS NULL OR octet_length(last_error_detail_nonce) = 24)
);
CREATE UNIQUE INDEX vault_rekey_jobs_active_uq
  ON vault_rekey_jobs (vault_id)
  WHERE status IN ('pending', 'distributing', 'rewrapping', 'verifying', 'ready');

CREATE TABLE legacy_migration_checkpoints (
  job_id uuid NOT NULL REFERENCES legacy_migration_jobs(id) ON DELETE CASCADE,
  stage text NOT NULL CHECK (stage IN ('preparing', 'frozen', 'encrypting', 'verifying', 'cutover')),
  cursor_kind text,
  cursor_value text,
  processed_count integer NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
  succeeded_count integer NOT NULL DEFAULT 0 CHECK (succeeded_count >= 0),
  failed_count integer NOT NULL DEFAULT 0 CHECK (failed_count >= 0),
  source_digest bytea CHECK (source_digest IS NULL OR octet_length(source_digest) = 32),
  target_digest bytea CHECK (target_digest IS NULL OR octet_length(target_digest) = 32),
  checkpoint_hash bytea NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
  encrypted_state bytea,
  encrypted_state_nonce bytea,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (job_id, stage),
  CHECK ((cursor_kind IS NULL) = (cursor_value IS NULL)),
  CHECK ((encrypted_state IS NULL) = (encrypted_state_nonce IS NULL)),
  CHECK (encrypted_state_nonce IS NULL OR octet_length(encrypted_state_nonce) = 24),
  CHECK (succeeded_count + failed_count <= processed_count)
);

CREATE TABLE legacy_migration_records (
  job_id uuid NOT NULL REFERENCES legacy_migration_jobs(id) ON DELETE CASCADE,
  source_kind text NOT NULL CHECK (source_kind IN ('vault_header', 'item_metadata', 'item_secret')),
  source_id text NOT NULL,
  source_version integer NOT NULL DEFAULT 1 CHECK (source_version > 0),
  target_record_id uuid,
  state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'encrypted', 'verified', 'failed')),
  source_digest bytea NOT NULL CHECK (octet_length(source_digest) = 32),
  target_digest bytea CHECK (target_digest IS NULL OR octet_length(target_digest) = 32),
  error_code text,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (job_id, source_kind, source_id, source_version),
  UNIQUE (job_id, target_record_id),
  CHECK ((state IN ('encrypted', 'verified')) = (target_record_id IS NOT NULL AND target_digest IS NOT NULL))
);

CREATE TABLE legacy_migration_evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id uuid NOT NULL REFERENCES legacy_migration_jobs(id) ON DELETE RESTRICT,
  evidence_type text NOT NULL CHECK (evidence_type IN ('source_snapshot', 'record_counts', 'ciphertext_digest', 'recipient_coverage', 'audit_chain_head', 'cutover', 'rollback', 'legacy_key_retirement')),
  stage text NOT NULL CHECK (stage IN ('legacy', 'preparing', 'frozen', 'encrypting', 'verifying', 'cutover', 'e2ee', 'failed')),
  subject_kind text CHECK (subject_kind IN ('vault', 'item', 'secret_version', 'recipient', 'audit_chain', 'deployment')),
  subject_id text,
  record_count integer CHECK (record_count IS NULL OR record_count >= 0),
  digest bytea NOT NULL CHECK (octet_length(digest) = 32),
  encrypted_payload bytea,
  encrypted_payload_nonce bytea,
  signer_device_id uuid REFERENCES user_devices(id) ON DELETE SET NULL,
  signature bytea CHECK (signature IS NULL OR octet_length(signature) = 64),
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((subject_kind IS NULL) = (subject_id IS NULL)),
  CHECK ((encrypted_payload IS NULL) = (encrypted_payload_nonce IS NULL)),
  CHECK (encrypted_payload_nonce IS NULL OR octet_length(encrypted_payload_nonce) = 24)
);
CREATE INDEX legacy_migration_evidence_job_idx
  ON legacy_migration_evidence (job_id, stage, evidence_type, created_at);

CREATE TABLE encrypted_client_commands (
  id uuid PRIMARY KEY,
  idempotency_key text NOT NULL,
  user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE CASCADE,
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  item_id uuid REFERENCES items(id) ON DELETE CASCADE,
  command_type text NOT NULL,
  protocol_version text NOT NULL DEFAULT 'lm-e2ee-v1',
  key_epoch integer NOT NULL CHECK (key_epoch > 0),
  expected_record_version integer CHECK (expected_record_version IS NULL OR expected_record_version >= 0),
  expected_secret_version integer CHECK (expected_secret_version IS NULL OR expected_secret_version >= 0),
  payload_ciphertext bytea NOT NULL CHECK (octet_length(payload_ciphertext) > 16),
  payload_nonce bytea NOT NULL CHECK (octet_length(payload_nonce) = 24),
  payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
  signature bytea NOT NULL CHECK (octet_length(signature) = 64),
  status text NOT NULL DEFAULT 'accepted' CHECK (status IN ('accepted', 'committed', 'conflict', 'rejected', 'expired')),
  result_code text,
  server_sequence bigint,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  committed_at timestamptz,
  FOREIGN KEY (item_id, vault_id) REFERENCES items(id, vault_id) ON DELETE CASCADE,
  FOREIGN KEY (vault_id, key_epoch) REFERENCES vault_key_epochs(vault_id, epoch),
  UNIQUE (user_id, idempotency_key),
  CHECK (expires_at > created_at),
  CHECK ((status <> 'committed') OR committed_at IS NOT NULL)
);
CREATE INDEX encrypted_client_commands_pending_idx
  ON encrypted_client_commands (device_id, status, created_at)
  WHERE status = 'accepted';
CREATE INDEX encrypted_client_commands_expiry_idx
  ON encrypted_client_commands (expires_at) WHERE status = 'accepted';

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
    IF EXISTS (
      SELECT 1 FROM vaults
      WHERE id = NEW.vault_id AND name <> ''
    ) OR EXISTS (
      SELECT 1 FROM items
      WHERE vault_id = NEW.vault_id
        AND (
          title <> ''
          OR kind <> 'secure_note'
          OR username IS NOT NULL
          OR origin IS NOT NULL
          OR tags <> '[]'::jsonb
          OR favorite
          OR sensitivity <> 'medium'
        )
    ) THEN
      RAISE EXCEPTION 'legacy plaintext metadata must be cleared before e2ee cutover';
    END IF;

    IF NOT EXISTS (
      SELECT 1 FROM vault_key_envelopes
      WHERE vault_id = NEW.vault_id
        AND key_epoch = NEW.active_epoch
        AND recipient_kind = 'enterprise_recovery'
        AND access_scope = 'recovery'
        AND status = 'active'
    ) THEN
      RAISE EXCEPTION 'enterprise recovery envelope is required before e2ee cutover';
    END IF;

    IF EXISTS (
      SELECT 1 FROM items i
      WHERE i.vault_id = NEW.vault_id
        AND NOT EXISTS (
          SELECT 1 FROM encrypted_item_metadata_versions metadata
          WHERE metadata.item_id = i.id
            AND metadata.record_version = i.version
            AND metadata.key_epoch = NEW.active_epoch
        )
    ) THEN
      RAISE EXCEPTION 'encrypted item metadata coverage is incomplete';
    END IF;

    IF EXISTS (
      SELECT 1 FROM item_secret_versions legacy_secret
      WHERE legacy_secret.vault_id = NEW.vault_id
        AND NOT EXISTS (
          SELECT 1
          FROM encrypted_item_secret_versions encrypted_secret
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
      SELECT 1 FROM audit_events audit_event
      WHERE audit_event.vault_id = NEW.vault_id
        AND audit_event.details <> '{}'::jsonb
    ) THEN
      RAISE EXCEPTION 'encrypted audit context coverage is incomplete';
    END IF;
  END IF;

  RETURN NEW;
END;
$$;
CREATE TRIGGER vault_crypto_states_guard_update
BEFORE UPDATE ON vault_crypto_states
FOR EACH ROW EXECUTE FUNCTION mima_guard_vault_crypto_state();

CREATE OR REPLACE FUNCTION mima_initialize_vault_crypto_state()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  INSERT INTO vault_crypto_states (vault_id) VALUES (NEW.id);
  RETURN NEW;
END;
$$;
CREATE TRIGGER vaults_initialize_crypto_state
AFTER INSERT ON vaults
FOR EACH ROW EXECUTE FUNCTION mima_initialize_vault_crypto_state();

CREATE OR REPLACE FUNCTION mima_guard_e2ee_vault_legacy_fields()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM vault_crypto_states
    WHERE vault_id = NEW.id AND storage_mode = 'e2ee'
  ) AND NEW.name <> '' THEN
    RAISE EXCEPTION 'e2ee vault name must be stored only in encrypted_vault_headers';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER vaults_guard_e2ee_legacy_fields
BEFORE UPDATE ON vaults
FOR EACH ROW EXECUTE FUNCTION mima_guard_e2ee_vault_legacy_fields();

CREATE OR REPLACE FUNCTION mima_guard_e2ee_item_legacy_fields()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM vault_crypto_states
    WHERE vault_id = NEW.vault_id AND storage_mode = 'e2ee'
  ) AND (
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
  RETURN NEW;
END;
$$;
CREATE TRIGGER items_guard_e2ee_legacy_fields
BEFORE INSERT OR UPDATE ON items
FOR EACH ROW EXECUTE FUNCTION mima_guard_e2ee_item_legacy_fields();

CREATE OR REPLACE FUNCTION mima_reject_legacy_secret_write()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM vault_crypto_states
    WHERE vault_id = NEW.vault_id AND storage_mode = 'e2ee'
  ) THEN
    RAISE EXCEPTION 'legacy secret writes are disabled for e2ee vaults';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER item_secret_versions_reject_e2ee_write
BEFORE INSERT OR UPDATE ON item_secret_versions
FOR EACH ROW EXECUTE FUNCTION mima_reject_legacy_secret_write();

CREATE OR REPLACE FUNCTION mima_guard_e2ee_audit_details()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF NEW.vault_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM vault_crypto_states
    WHERE vault_id = NEW.vault_id AND storage_mode = 'e2ee'
  ) AND NEW.details <> '{}'::jsonb THEN
    RAISE EXCEPTION 'e2ee audit details must not contain metadata';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER audit_events_guard_e2ee_details
BEFORE INSERT OR UPDATE ON audit_events
FOR EACH ROW EXECUTE FUNCTION mima_guard_e2ee_audit_details();

CREATE OR REPLACE FUNCTION mima_guard_migration_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  allowed boolean := false;
BEGIN
  IF NEW.state = OLD.state THEN
    RETURN NEW;
  END IF;

  allowed := CASE OLD.state
    WHEN 'legacy' THEN NEW.state = 'preparing'
    WHEN 'preparing' THEN NEW.state IN ('frozen', 'failed')
    WHEN 'frozen' THEN NEW.state IN ('encrypting', 'failed')
    WHEN 'encrypting' THEN NEW.state IN ('verifying', 'failed')
    WHEN 'verifying' THEN NEW.state IN ('cutover', 'failed')
    WHEN 'cutover' THEN NEW.state = 'e2ee'
    WHEN 'failed' THEN NEW.state = 'legacy'
    WHEN 'e2ee' THEN false
    ELSE false
  END;

  IF NOT allowed THEN
    RAISE EXCEPTION 'invalid legacy migration transition: % -> %', OLD.state, NEW.state;
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER legacy_migration_jobs_guard_transition
BEFORE UPDATE OF state ON legacy_migration_jobs
FOR EACH ROW EXECUTE FUNCTION mima_guard_migration_transition();

CREATE OR REPLACE FUNCTION mima_prevent_completed_migration_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.state IN ('cutover', 'e2ee') THEN
    RAISE EXCEPTION 'cutover migration evidence cannot be deleted';
  END IF;
  RETURN OLD;
END;
$$;
CREATE TRIGGER legacy_migration_jobs_guard_delete
BEFORE DELETE ON legacy_migration_jobs
FOR EACH ROW EXECUTE FUNCTION mima_prevent_completed_migration_delete();
