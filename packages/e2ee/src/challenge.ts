import { signBytes, verifyBytes } from './asymmetric.ts';
import { E2EE_PROTOCOL, E2eeError } from './constants.ts';
import {
  assertIdentifier,
  assertProtocol,
  canonicalJson,
  fromBase64Url,
  sodiumReady,
  toBase64Url,
  utf8,
  type JsonValue,
} from './encoding.ts';

const CHALLENGE_NONCE_BYTES = 32;

export interface UnlockChallenge {
  protocol: typeof E2EE_PROTOCOL;
  kind: 'unlock-challenge';
  challengeId: string;
  accountId: string;
  deviceId: string;
  sessionId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
}

export interface SignedUnlockChallenge extends UnlockChallenge {
  signature: string;
}

export async function createUnlockChallenge(input: {
  challengeId: string;
  accountId: string;
  deviceId: string;
  sessionId: string;
  issuedAt: string;
  expiresAt: string;
}): Promise<UnlockChallenge> {
  const crypto = await sodiumReady();
  const nonce = crypto.randombytes_buf(CHALLENGE_NONCE_BYTES);
  try {
    const challenge: UnlockChallenge = {
      protocol: E2EE_PROTOCOL,
      kind: 'unlock-challenge',
      ...input,
      nonce: await toBase64Url(nonce),
    };
    await validateUnlockChallenge(challenge);
    return challenge;
  } finally {
    crypto.memzero(nonce);
  }
}

export async function signUnlockChallenge(
  challenge: UnlockChallenge,
  deviceSigningPrivateKey: Uint8Array,
): Promise<SignedUnlockChallenge> {
  await validateUnlockChallenge(challenge);
  const message = unlockChallengeBytes(challenge);
  try {
    return {
      ...challenge,
      signature: await signBytes(message, deviceSigningPrivateKey),
    };
  } finally {
    message.fill(0);
  }
}

export async function verifyUnlockChallenge(
  challenge: SignedUnlockChallenge,
  trustedDeviceSigningPublicKey: string,
): Promise<boolean> {
  await validateUnlockChallenge(challenge);
  const message = unlockChallengeBytes(challenge);
  try {
    return await verifyBytes(challenge.signature, message, trustedDeviceSigningPublicKey);
  } finally {
    message.fill(0);
  }
}

export async function validateUnlockChallenge(challenge: UnlockChallenge): Promise<void> {
  assertProtocol(challenge.protocol);
  if (challenge.kind !== 'unlock-challenge') {
    throw new E2eeError('unsupported_protocol', 'Unsupported challenge kind');
  }
  assertIdentifier(challenge.challengeId, 'challengeId');
  assertIdentifier(challenge.accountId, 'accountId');
  assertIdentifier(challenge.deviceId, 'deviceId');
  assertIdentifier(challenge.sessionId, 'sessionId');
  const nonce = await fromBase64Url(challenge.nonce, CHALLENGE_NONCE_BYTES);
  nonce.fill(0);
  const issuedAt = Date.parse(challenge.issuedAt);
  const expiresAt = Date.parse(challenge.expiresAt);
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) {
    throw new E2eeError('invalid_input', 'Challenge timestamps are invalid');
  }
}

export function unlockChallengeBytes(challenge: UnlockChallenge): Uint8Array {
  const body: JsonValue = {
    accountId: challenge.accountId,
    challengeId: challenge.challengeId,
    deviceId: challenge.deviceId,
    expiresAt: challenge.expiresAt,
    issuedAt: challenge.issuedAt,
    kind: challenge.kind,
    nonce: challenge.nonce,
    protocol: challenge.protocol,
    sessionId: challenge.sessionId,
  };
  return utf8(canonicalJson(body));
}
