ALTER TABLE vault_ownership_transfer_requests
  ADD COLUMN acceptance_required boolean NOT NULL DEFAULT true,
  ADD COLUMN acceptance_idempotency_key text,
  ADD COLUMN accepted_by_device_id uuid REFERENCES user_devices(id) ON DELETE RESTRICT,
  ADD COLUMN acceptance_digest bytea,
  ADD COLUMN acceptance_signature bytea,
  ADD COLUMN accepted_at timestamptz;

ALTER TABLE vault_ownership_transfer_requests
  DROP CONSTRAINT IF EXISTS vault_ownership_transfer_requests_envelope_task_id_key;

CREATE UNIQUE INDEX vault_ownership_transfer_requests_pending_task_uq
  ON vault_ownership_transfer_requests (envelope_task_id)
  WHERE status = 'pending';

UPDATE vault_ownership_transfer_requests
SET acceptance_required = false
WHERE status IN ('completed', 'cancelled');

ALTER TABLE vault_ownership_transfer_requests
  ADD CONSTRAINT vault_ownership_transfer_acceptance_bundle_ck CHECK (
    (
      acceptance_idempotency_key IS NULL
      AND accepted_by_device_id IS NULL
      AND acceptance_digest IS NULL
      AND acceptance_signature IS NULL
      AND accepted_at IS NULL
    )
    OR
    (
      acceptance_idempotency_key IS NOT NULL
      AND length(acceptance_idempotency_key) BETWEEN 8 AND 80
      AND accepted_by_device_id IS NOT NULL
      AND acceptance_digest IS NOT NULL
      AND octet_length(acceptance_digest) = 32
      AND acceptance_signature IS NOT NULL
      AND octet_length(acceptance_signature) = 64
      AND accepted_at IS NOT NULL
    )
  ),
  ADD CONSTRAINT vault_ownership_transfer_pending_acceptance_ck CHECK (
    status <> 'pending' OR acceptance_required
  ),
  ADD CONSTRAINT vault_ownership_transfer_completed_acceptance_ck CHECK (
    status <> 'completed' OR NOT acceptance_required OR accepted_at IS NOT NULL
  );

CREATE INDEX vault_ownership_transfer_acceptance_device_idx
  ON vault_ownership_transfer_requests (accepted_by_device_id, accepted_at)
  WHERE accepted_by_device_id IS NOT NULL;
