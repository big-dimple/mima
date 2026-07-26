ALTER TABLE user_devices
  ALTER COLUMN encrypted_private_key_bundle DROP NOT NULL,
  ALTER COLUMN private_key_bundle_nonce DROP NOT NULL,
  ALTER COLUMN encrypted_label DROP NOT NULL,
  ALTER COLUMN label_nonce DROP NOT NULL;

ALTER TABLE user_devices ADD CONSTRAINT user_devices_private_bundle_pair_ck
  CHECK ((encrypted_private_key_bundle IS NULL) = (private_key_bundle_nonce IS NULL));
ALTER TABLE user_devices ADD CONSTRAINT user_devices_encrypted_label_pair_ck
  CHECK ((encrypted_label IS NULL) = (label_nonce IS NULL));

ALTER TABLE user_crypto_profiles
  ALTER COLUMN encrypted_private_key_bundle DROP NOT NULL,
  ALTER COLUMN private_key_bundle_nonce DROP NOT NULL;
ALTER TABLE user_crypto_profiles ADD CONSTRAINT user_crypto_profiles_private_bundle_pair_ck
  CHECK ((encrypted_private_key_bundle IS NULL) = (private_key_bundle_nonce IS NULL));

-- Enrollment requests are short-lived and cannot be safely backfilled with a client-chosen
-- device id. Invalidate them so every new approval is bound to the claimed device exactly.
DELETE FROM device_enrollment_requests;
ALTER TABLE device_enrollment_requests
  ADD COLUMN requested_device_id uuid NOT NULL,
  ALTER COLUMN encrypted_label DROP NOT NULL,
  ALTER COLUMN label_nonce DROP NOT NULL;
ALTER TABLE device_enrollment_requests ADD CONSTRAINT device_enrollment_requests_label_pair_ck
  CHECK ((encrypted_label IS NULL) = (label_nonce IS NULL));

ALTER TABLE device_enrollment_requests
  DROP CONSTRAINT device_enrollment_requests_check1,
  DROP CONSTRAINT device_enrollment_requests_check2,
  ADD COLUMN approval_algorithm text;
ALTER TABLE device_enrollment_requests ADD CONSTRAINT device_enrollment_requests_approval_algorithm_ck
  CHECK (approval_algorithm IS NULL OR approval_algorithm = 'x25519-sealed-box');
ALTER TABLE device_enrollment_requests ADD CONSTRAINT device_enrollment_requests_approval_payload_ck
  CHECK (
    (approval_ciphertext IS NULL AND approval_algorithm IS NULL AND approval_nonce IS NULL)
    OR
    (approval_ciphertext IS NOT NULL AND approval_algorithm = 'x25519-sealed-box' AND approval_nonce IS NULL)
  );
ALTER TABLE device_enrollment_requests ADD CONSTRAINT device_enrollment_requests_approved_payload_ck
  CHECK (
    status NOT IN ('approved', 'claimed')
    OR (approval_ciphertext IS NOT NULL AND approval_algorithm = 'x25519-sealed-box' AND approval_signature IS NOT NULL)
  );

-- Challenges are intentionally short-lived and carry no durable user data. Old rows
-- cannot be upgraded with a trustworthy random nonce, so invalidate them explicitly.
DELETE FROM session_unlock_challenges;
ALTER TABLE session_unlock_challenges
  ADD COLUMN challenge_nonce bytea NOT NULL CHECK (octet_length(challenge_nonce) = 32);
