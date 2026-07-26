export const E2EE_PROTOCOL = 'lm-e2ee-v1' as const;

export const KDF_ALGORITHM = 'argon2id13' as const;
export const KDF_ITERATIONS = 3;
export const KDF_MEMORY_KIB = 65_536;
export const KDF_PARALLELISM = 1;
export const KDF_SALT_BYTES = 16;
export const KEY_BYTES = 32;

export const AEAD_ALGORITHM = 'xchacha20-poly1305-ietf' as const;
export const AEAD_NONCE_BYTES = 24;
export const AAD_VERSION = 1 as const;

export const SEALED_BOX_ALGORITHM = 'x25519-xsalsa20-poly1305-sealed-box' as const;
export const SIGNATURE_ALGORITHM = 'ed25519' as const;

export type E2eeErrorCode =
  | 'authentication_failed'
  | 'invalid_input'
  | 'unsupported_protocol'
  | 'verification_failed';

export class E2eeError extends Error {
  readonly code: E2eeErrorCode;

  constructor(code: E2eeErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'E2eeError';
    this.code = code;
  }
}
