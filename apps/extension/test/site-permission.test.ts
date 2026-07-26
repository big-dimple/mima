import { describe, expect, it } from 'vitest';
import { sitePermissionPattern } from '../src/site-permission.ts';

describe('site permission pattern', () => {
  it('requests only the active HTTP(S) host and leaves exact port checks to matching', () => {
    expect(sitePermissionPattern('https://accounts.example.test')).toBe('https://accounts.example.test/*');
    expect(sitePermissionPattern('http://internal.example.test:8080')).toBe('http://internal.example.test/*');
  });

  it('rejects non-web and malformed origins', () => {
    expect(sitePermissionPattern('ftp://files.example.test')).toBeNull();
    expect(sitePermissionPattern('not a URL')).toBeNull();
  });
});
