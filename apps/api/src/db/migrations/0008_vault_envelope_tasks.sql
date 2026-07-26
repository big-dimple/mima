CREATE TABLE vault_envelope_tasks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  key_epoch integer NOT NULL CHECK (key_epoch > 0),
  authorization_kind text NOT NULL
    CHECK (authorization_kind IN ('direct', 'custom_group', 'directory_group')),
  authorization_ref text NOT NULL,
  recipient_user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  capability text NOT NULL CHECK (capability IN ('metadata', 'full')),
  expected_profile_generation integer CHECK (expected_profile_generation > 0),
  status text NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'completed', 'cancelled')),
  completed_envelope_id uuid REFERENCES vault_key_envelopes(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  cancelled_at timestamptz,
  FOREIGN KEY (vault_id, key_epoch)
    REFERENCES vault_key_epochs(vault_id, epoch)
    ON DELETE CASCADE,
  CHECK (
    (status = 'pending' AND completed_envelope_id IS NULL AND completed_at IS NULL AND cancelled_at IS NULL)
    OR (status = 'completed' AND completed_envelope_id IS NOT NULL AND completed_at IS NOT NULL AND cancelled_at IS NULL)
    OR (status = 'cancelled' AND completed_envelope_id IS NULL AND completed_at IS NULL AND cancelled_at IS NOT NULL)
  )
);

CREATE UNIQUE INDEX vault_envelope_tasks_pending_uq
  ON vault_envelope_tasks (
    vault_id,
    key_epoch,
    authorization_kind,
    authorization_ref,
    recipient_user_id,
    capability
  )
  WHERE status = 'pending';
CREATE INDEX vault_envelope_tasks_owner_idx
  ON vault_envelope_tasks (vault_id, key_epoch, status, created_at);
CREATE INDEX vault_envelope_tasks_recipient_idx
  ON vault_envelope_tasks (recipient_user_id, status, updated_at);
CREATE INDEX vault_envelope_tasks_authorization_idx
  ON vault_envelope_tasks (authorization_kind, authorization_ref, status);

CREATE TABLE vault_ownership_transfer_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  vault_id uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  from_owner_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  to_owner_user_id text NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  envelope_task_id uuid NOT NULL UNIQUE REFERENCES vault_envelope_tasks(id) ON DELETE CASCADE,
  expected_access_generation integer NOT NULL CHECK (expected_access_generation >= 0),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'cancelled')),
  requested_by_device_id uuid NOT NULL REFERENCES user_devices(id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz,
  cancelled_at timestamptz,
  CHECK (from_owner_user_id <> to_owner_user_id),
  CHECK (
    (status = 'pending' AND completed_at IS NULL AND cancelled_at IS NULL)
    OR (status = 'completed' AND completed_at IS NOT NULL AND cancelled_at IS NULL)
    OR (status = 'cancelled' AND completed_at IS NULL AND cancelled_at IS NOT NULL)
  )
);
CREATE UNIQUE INDEX vault_ownership_transfer_requests_active_uq
  ON vault_ownership_transfer_requests (vault_id)
  WHERE status = 'pending';
CREATE INDEX vault_ownership_transfer_requests_target_idx
  ON vault_ownership_transfer_requests (to_owner_user_id, status, created_at);
