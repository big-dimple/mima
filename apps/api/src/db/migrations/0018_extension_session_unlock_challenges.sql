ALTER TABLE session_unlock_challenges
  ALTER COLUMN session_id DROP NOT NULL,
  ADD COLUMN extension_session_id uuid REFERENCES extension_sessions(id) ON DELETE CASCADE;

ALTER TABLE session_unlock_challenges
  ADD CONSTRAINT session_unlock_challenges_session_source_ck
  CHECK (num_nonnulls(session_id, extension_session_id) = 1);

CREATE INDEX session_unlock_challenges_extension_session_idx
  ON session_unlock_challenges (extension_session_id, expires_at);
