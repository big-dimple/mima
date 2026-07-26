CREATE OR REPLACE FUNCTION enforce_vault_header_format_nondowngrade()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  active_format integer;
BEGIN
  SELECT header.schema_version
  INTO active_format
  FROM vault_crypto_states AS state
  JOIN encrypted_vault_headers AS header
    ON header.vault_id = state.vault_id
   AND header.header_version = state.active_header_version
   AND header.key_epoch = state.active_epoch
  WHERE state.vault_id = NEW.vault_id;

  IF active_format IS NOT NULL AND NEW.schema_version < active_format THEN
    RAISE EXCEPTION 'vault header format downgrade is not allowed'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS encrypted_vault_headers_format_nondowngrade
  ON encrypted_vault_headers;
CREATE TRIGGER encrypted_vault_headers_format_nondowngrade
BEFORE INSERT ON encrypted_vault_headers
FOR EACH ROW
EXECUTE FUNCTION enforce_vault_header_format_nondowngrade();
