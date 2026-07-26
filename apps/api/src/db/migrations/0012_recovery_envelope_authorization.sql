DO $$
DECLARE
  recipient_constraint text;
BEGIN
  SELECT conname INTO recipient_constraint
  FROM pg_constraint
  WHERE conrelid = 'vault_key_envelopes'::regclass
    AND contype = 'u'
    AND pg_get_constraintdef(oid) LIKE
      'UNIQUE (vault_id, key_epoch, recipient_kind, recipient_key_fingerprint, access_scope)%';

  IF recipient_constraint IS NULL THEN
    RAISE EXCEPTION 'vault key envelope recipient constraint is missing';
  END IF;

  EXECUTE format(
    'ALTER TABLE vault_key_envelopes DROP CONSTRAINT %I',
    recipient_constraint
  );
END;
$$;

CREATE UNIQUE INDEX vault_key_envelopes_recipient_authorization_uq
  ON vault_key_envelopes (
    vault_id,
    key_epoch,
    recipient_kind,
    recipient_key_fingerprint,
    access_scope,
    authorization_kind,
    COALESCE(authorization_ref, '')
  );
