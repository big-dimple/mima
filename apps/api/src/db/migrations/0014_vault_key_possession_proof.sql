ALTER TABLE vault_key_epochs
  ADD COLUMN key_possession_public_key bytea;

ALTER TABLE vault_key_epochs
  ADD CONSTRAINT vault_key_epochs_possession_public_key_ck CHECK (
    key_possession_public_key IS NULL OR octet_length(key_possession_public_key) = 32
  );

ALTER TABLE vault_ownership_transfer_requests
  ADD COLUMN key_possession_signature bytea,
  ADD COLUMN accepted_key_epoch integer;

UPDATE vault_ownership_transfer_requests
SET
  status = 'cancelled',
  cancelled_at = COALESCE(cancelled_at, now()),
  updated_at = now()
WHERE status = 'pending';

ALTER TABLE vault_ownership_transfer_requests
  ADD CONSTRAINT vault_ownership_transfer_key_possession_bundle_ck CHECK (
    (
      key_possession_signature IS NULL
      AND accepted_key_epoch IS NULL
    )
    OR
    (
      key_possession_signature IS NOT NULL
      AND octet_length(key_possession_signature) = 64
      AND accepted_key_epoch IS NOT NULL
      AND accepted_key_epoch > 0
    )
  ),
  ADD CONSTRAINT vault_ownership_transfer_completed_possession_ck CHECK (
    status <> 'completed'
    OR NOT acceptance_required
    OR (
      key_possession_signature IS NOT NULL
      AND accepted_key_epoch IS NOT NULL
    )
  ),
  ADD CONSTRAINT vault_ownership_transfer_accepted_epoch_fk FOREIGN KEY (vault_id, accepted_key_epoch)
    REFERENCES vault_key_epochs(vault_id, epoch)
    ON DELETE RESTRICT;
