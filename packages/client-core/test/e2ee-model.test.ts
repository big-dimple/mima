import { describe, expect, it } from 'vitest';
import { parseItemMetadataPayload, parseVaultHeaderPayload } from '../src/e2ee-model.ts';

const metadata = {
  kind: 'login' as const,
  title: '共享入口',
  username: null,
  origin: 'https://example.test',
  tags: [],
  favorite: false,
  sensitivity: 'medium' as const,
};

describe('encrypted item metadata secret state', () => {
  it('treats legacy metadata without a state as containing a secret', () => {
    expect(parseItemMetadataPayload(metadata).secretState).toBe('present');
  });

  it('allows an absent secret only for login entries', () => {
    expect(parseItemMetadataPayload({ ...metadata, secretState: 'absent' }).secretState).toBe('absent');
    expect(() => parseItemMetadataPayload({
      ...metadata,
      kind: 'api_token',
      secretState: 'absent',
    })).toThrow('只有账号密码可以不保存密码');
  });
});

describe('encrypted item metadata login URLs', () => {
  it('upgrades the legacy primary URL into an ordered URL list', () => {
    expect(parseItemMetadataPayload({
      ...metadata,
      loginUrl: 'https://example.test/login',
    })).toMatchObject({
      origin: 'https://example.test',
      loginUrl: 'https://example.test/login',
      loginUrls: ['https://example.test/login'],
    });
  });

  it('normalizes and deduplicates the ordered URL list', () => {
    expect(parseItemMetadataPayload({
      ...metadata,
      loginUrls: [
        'https://example.test/first',
        'https://second.example.test',
        'https://example.test/first',
      ],
    }).loginUrls).toEqual([
      'https://example.test/first',
      'https://second.example.test/',
    ]);
  });

  it('rejects invalid and over-limit URL lists', () => {
    expect(() => parseItemMetadataPayload({ ...metadata, loginUrls: ['javascript:alert(1)'] }))
      .toThrow('网址格式不正确');
    expect(() => parseItemMetadataPayload({
      ...metadata,
      loginUrls: Array.from({ length: 11 }, (_, index) => `https://${index}.example.test`),
    })).toThrow('网址格式不正确');
  });
});

describe('encrypted vault header payload', () => {
  it('keeps legacy headers compatible by treating a missing group as ungrouped', () => {
    expect(parseVaultHeaderPayload({ name: '运维库', directories: [] })).toEqual({
      name: '运维库',
      directories: [],
      vaultGroupName: null,
    });
  });

  it('normalizes an encrypted vault group without exposing it to the server model', () => {
    expect(parseVaultHeaderPayload({
      name: '示例云项目',
      directories: [],
      vaultGroupName: ' 运维 ',
    }).vaultGroupName).toBe('运维');
  });

  it('rejects malformed vault group names before they enter local state', () => {
    expect(() => parseVaultHeaderPayload({
      name: '示例云项目',
      directories: [],
      vaultGroupName: 'a'.repeat(61),
    })).toThrow('密码库旧版设置格式不正确');
    expect(() => parseVaultHeaderPayload({
      name: '示例云项目',
      directories: [],
      vaultGroupName: '运维\u0000组',
    })).toThrow('密码库旧版设置格式不正确');
  });
});
