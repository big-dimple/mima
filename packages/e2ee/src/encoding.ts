import sodium from 'libsodium-wrappers-sumo';
import { E2eeError } from './constants.ts';

export type JsonPrimitive = boolean | null | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export async function sodiumReady(): Promise<typeof sodium> {
  await sodium.ready;
  return sodium;
}

export function canonicalJson(value: JsonValue): string {
  return canonicalize(value, new Set<object>());
}

function canonicalize(value: JsonValue, ancestors: Set<object>): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new E2eeError('invalid_input', 'JSON numbers must be finite');
    }
    return JSON.stringify(value);
  }
  if (ancestors.has(value)) {
    throw new E2eeError('invalid_input', 'JSON value must not contain cycles');
  }

  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => canonicalize(entry, ancestors)).join(',')}]`;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      throw new E2eeError('invalid_input', 'JSON objects must be plain objects');
    }
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key]!, ancestors)}`)
      .join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function decodeUtf8(value: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(value);
  } catch (error) {
    throw new E2eeError('invalid_input', 'Value is not valid UTF-8', { cause: error });
  }
}

export function encodeJson(value: JsonValue): Uint8Array {
  return utf8(canonicalJson(value));
}

export function decodeJson(value: Uint8Array): JsonValue {
  try {
    return JSON.parse(decodeUtf8(value)) as JsonValue;
  } catch (error) {
    if (error instanceof E2eeError) {
      throw error;
    }
    throw new E2eeError('invalid_input', 'Value is not valid JSON', { cause: error });
  }
}

export async function toBase64Url(value: Uint8Array): Promise<string> {
  const crypto = await sodiumReady();
  return crypto.to_base64(value, crypto.base64_variants.URLSAFE_NO_PADDING);
}

export async function fromBase64Url(value: string, expectedBytes?: number): Promise<Uint8Array> {
  const crypto = await sodiumReady();
  let decoded: Uint8Array;
  try {
    decoded = crypto.from_base64(value, crypto.base64_variants.URLSAFE_NO_PADDING);
  } catch (error) {
    throw new E2eeError('invalid_input', 'Value is not valid base64url', { cause: error });
  }
  if (expectedBytes !== undefined && decoded.byteLength !== expectedBytes) {
    crypto.memzero(decoded);
    throw new E2eeError('invalid_input', `Expected ${expectedBytes} bytes`);
  }
  return decoded;
}

export function assertIdentifier(value: string, name: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.length > 512) {
    throw new E2eeError('invalid_input', `${name} must be a non-empty string`);
  }
}

export function assertPositiveVersion(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new E2eeError('invalid_input', `${name} must be a positive safe integer`);
  }
}

export function assertProtocol(value: string): void {
  if (value !== 'lm-e2ee-v1') {
    throw new E2eeError('unsupported_protocol', `Unsupported E2EE protocol: ${value}`);
  }
}
