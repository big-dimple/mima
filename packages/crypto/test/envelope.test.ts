import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  FileMasterKeyProvider,
  encryptSecret,
  decryptSecret,
  rewrapDek,
  aadBytes,
  canonicalJson,
  computeAuditHash,
  AUDIT_CHAIN_GENESIS,
  type SecretAad,
} from '../src/index.ts';

function makeKeyDir(versions = 1): string {
  const dir = mkdtempSync(join(tmpdir(), 'mima-keys-'));
  for (let v = 1; v <= versions; v++) {
    writeFileSync(join(dir, `kek-v${v}.key`), randomBytes(32).toString('hex'), { mode: 0o600 });
  }
  return dir;
}

const aad: SecretAad = {
  vaultId: '11111111-1111-4111-8111-111111111111',
  itemId: '22222222-2222-4222-8222-222222222222',
  secretVersion: 1,
  itemKind: 'login',
};

describe('envelope encryption', () => {
  it('加密后可解密还原（含中文与多行）', () => {
    const keys = new FileMasterKeyProvider(makeKeyDir());
    const plaintext = '测试密码-abc\n第二行 !@#';
    const enc = encryptSecret(keys, aad, plaintext);
    expect(decryptSecret(keys, aad, enc)).toBe(plaintext);
  });

  it('密文不包含明文字节', () => {
    const keys = new FileMasterKeyProvider(makeKeyDir());
    const enc = encryptSecret(keys, aad, 'super-unique-plaintext-marker');
    expect(enc.ciphertext.includes(Buffer.from('super-unique-plaintext-marker'))).toBe(false);
  });

  it('AAD 任一字段不同则解密失败（防止密文移用）', () => {
    const keys = new FileMasterKeyProvider(makeKeyDir());
    const enc = encryptSecret(keys, aad, 'value');
    expect(() => decryptSecret(keys, { ...aad, secretVersion: 2 }, enc)).toThrow();
    expect(() => decryptSecret(keys, { ...aad, itemKind: 'api_token' }, enc)).toThrow();
    expect(() =>
      decryptSecret(keys, { ...aad, itemId: '33333333-3333-4333-8333-333333333333' }, enc),
    ).toThrow();
  });

  it('篡改密文/ tag / wrappedDek 解密失败', () => {
    const keys = new FileMasterKeyProvider(makeKeyDir());
    const enc = encryptSecret(keys, aad, 'value');
    const flip = (buf: Buffer) => {
      const copy = Buffer.from(buf);
      copy[0] = copy[0]! ^ 0xff;
      return copy;
    };
    expect(() => decryptSecret(keys, aad, { ...enc, ciphertext: flip(enc.ciphertext) })).toThrow();
    expect(() => decryptSecret(keys, aad, { ...enc, authTag: flip(enc.authTag) })).toThrow();
    expect(() => decryptSecret(keys, aad, { ...enc, wrappedDek: flip(enc.wrappedDek) })).toThrow();
  });

  it('rewrap 到新 KEK 后密文不变且仍可解密', () => {
    const dir = makeKeyDir(2);
    const keys = new FileMasterKeyProvider(dir);
    expect(keys.activeVersion()).toBe('v2');
    // 用 v1 加密（模拟旧数据）
    const keysV1Only = {
      getKey: (v: string) => keys.getKey(v),
      activeVersion: () => 'v1',
      listVersions: () => keys.listVersions(),
    };
    const enc = encryptSecret(keysV1Only, aad, 'rotate-me');
    const rewrapped = rewrapDek(keys, aad, enc.wrappedDek, 'v1', 'v2');
    expect(rewrapped.equals(enc.wrappedDek)).toBe(false);
    expect(
      decryptSecret(keys, aad, { ...enc, wrappedDek: rewrapped, keyVersion: 'v2' }),
    ).toBe('rotate-me');
  });

  it('aadBytes 稳定可重现', () => {
    expect(aadBytes(aad).equals(aadBytes({ ...aad }))).toBe(true);
  });
});

describe('audit hash chain', () => {
  const event = {
    ts: '2026-07-16T00:00:00.000Z',
    actorUserId: 'u-1',
    action: 'item.reveal',
    vaultId: null,
    itemId: null,
    success: true,
    details: { b: 2, a: 1 },
  };

  it('canonicalJson 键序稳定', () => {
    expect(canonicalJson({ b: 2, a: 1 })).toBe('{"a":1,"b":2}');
    expect(canonicalJson({ a: 1, b: 2 })).toBe(canonicalJson({ b: 2, a: 1 }));
  });

  it('同一事件哈希一致，篡改后不一致，密钥不同则不同（HMAC）', () => {
    const key = Buffer.alloc(32, 7);
    const h1 = computeAuditHash(key, AUDIT_CHAIN_GENESIS, event);
    expect(computeAuditHash(key, AUDIT_CHAIN_GENESIS, { ...event })).toBe(h1);
    expect(computeAuditHash(key, AUDIT_CHAIN_GENESIS, { ...event, success: false })).not.toBe(h1);
    expect(computeAuditHash(key, 'other-prev', event)).not.toBe(h1);
    // 独立密钥：不知道审计密钥无法重算合法链
    expect(computeAuditHash(Buffer.alloc(32, 8), AUDIT_CHAIN_GENESIS, event)).not.toBe(h1);
  });
});
