import { describe, expect, it } from 'vitest';
import { extensionItemMatchScore, extensionItemMatchesSite } from '../src/site-match.ts';
import type { DecryptedExtensionItem } from '../src/protocol.ts';

const item = {
  id: 'item-1',
  vaultId: 'vault-1',
  kind: 'login',
  title: '示例云子账号',
  username: 'alice',
  origin: 'https://accounts.example.test',
  loginUrl: 'https://accounts.example.test/login/tenant/example-b',
  loginUrls: [
    'https://accounts.example.test/login/tenant/example-b',
    'https://console.example.test/sign-in',
  ],
  tags: [],
  favorite: false,
  sensitivity: 'medium',
  secretState: 'present',
  version: 1,
  secretVersion: 1,
  keyEpoch: 1,
} satisfies DecryptedExtensionItem;

describe('extension site matching', () => {
  it('prioritizes the exact saved login path', () => {
    const site = { origin: item.origin, url: item.loginUrl };
    expect(extensionItemMatchScore(item, site)).toBe(2);
  });

  it('keeps same-origin redirects fillable', () => {
    const site = { origin: item.origin, url: 'https://accounts.example.test/login/redirected' };
    expect(extensionItemMatchScore(item, site)).toBe(1);
  });

  it('matches an exact secondary URL and its same-origin redirects', () => {
    expect(extensionItemMatchScore(item, {
      origin: 'https://console.example.test',
      url: 'https://console.example.test/sign-in',
    })).toBe(2);
    expect(extensionItemMatchScore(item, {
      origin: 'https://console.example.test',
      url: 'https://console.example.test/redirected',
    })).toBe(1);
  });

  it('normalizes legacy full URLs stored in origin', () => {
    const legacy = { ...item, origin: item.loginUrl, loginUrl: null, loginUrls: undefined };
    const site = { origin: item.origin, url: item.loginUrl };
    expect(extensionItemMatchesSite(legacy, site)).toBe(true);
  });

  it('rejects a different protocol, host, or port', () => {
    expect(extensionItemMatchesSite(item, {
      origin: 'http://accounts.example.test',
      url: 'http://accounts.example.test/login/tenant/example-b',
    })).toBe(false);
    expect(extensionItemMatchesSite(item, {
      origin: 'https://login.accounts.example.test',
      url: 'https://login.accounts.example.test/login',
    })).toBe(false);
    expect(extensionItemMatchesSite(item, {
      origin: 'https://accounts.example.test:8443',
      url: 'https://accounts.example.test:8443/login',
    })).toBe(false);
  });
});
