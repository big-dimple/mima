ALTER TABLE vaults
  ADD COLUMN parent_vault_id uuid;

ALTER TABLE vaults
  ADD CONSTRAINT vaults_parent_vault_fk
  FOREIGN KEY (parent_vault_id)
  REFERENCES vaults(id)
  ON DELETE RESTRICT;

ALTER TABLE vaults
  ADD CONSTRAINT vaults_project_kind_check
  CHECK (parent_vault_id IS NULL OR kind = 'team');

CREATE INDEX vaults_parent_vault_idx
  ON vaults(parent_vault_id)
  WHERE parent_vault_id IS NOT NULL;

CREATE OR REPLACE FUNCTION mima_guard_vault_project_relation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  parent_kind text;
  grandparent_vault_id uuid;
BEGIN
  IF TG_OP = 'UPDATE' AND OLD.parent_vault_id IS DISTINCT FROM NEW.parent_vault_id THEN
    RAISE EXCEPTION 'vault project relation is immutable';
  END IF;

  IF NEW.parent_vault_id IS NULL THEN
    RETURN NEW;
  END IF;

  IF NEW.kind <> 'team' THEN
    RAISE EXCEPTION 'only team vaults can be projects';
  END IF;

  IF NEW.parent_vault_id = NEW.id THEN
    RAISE EXCEPTION 'vault cannot be its own project parent';
  END IF;

  SELECT kind, parent_vault_id
    INTO parent_kind, grandparent_vault_id
  FROM vaults
  WHERE id = NEW.parent_vault_id
  FOR KEY SHARE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'project parent vault does not exist';
  END IF;

  IF parent_kind <> 'team' OR grandparent_vault_id IS NOT NULL THEN
    RAISE EXCEPTION 'project parent must be a root team vault';
  END IF;

  RETURN NEW;
END;
$$;

CREATE TRIGGER vaults_project_relation_guard
BEFORE INSERT OR UPDATE OF parent_vault_id, kind ON vaults
FOR EACH ROW
EXECUTE FUNCTION mima_guard_vault_project_relation();
