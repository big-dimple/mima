import { describe, expect, it } from 'vitest';
import { oidcUserId, parseGroupMap } from '../../src/auth/directory.ts';
import { toSessionUser } from '../../src/auth/contracts.ts';
import { assertFreshReauthentication } from '../../src/auth/oidc.ts';

describe('OIDC identity and directory boundaries', () => {
  it('keys users only by issuer and immutable subject', () => {
    const issuer = 'https://authentik.example.test/application/o/mima/';
    expect(oidcUserId(issuer, 'user-uuid')).toBe(oidcUserId(issuer, 'user-uuid'));
    expect(oidcUserId(issuer, 'user-uuid')).not.toBe(oidcUserId(issuer, 'other-user-uuid'));
    expect(oidcUserId(issuer, 'user-uuid')).not.toBe(
      oidcUserId('https://other.example.test/application/o/mima/', 'user-uuid'),
    );
  });

  it('accepts only explicit, unambiguous internal group references', () => {
    const mapping = parseGroupMap(JSON.stringify({
      'authentik-platform-uuid': 'group:default/platform',
      qa: 'group:default/qa',
    }));
    expect(mapping.get('authentik-platform-uuid')).toBe('group:default/platform');
    expect(mapping.get('unknown')).toBeUndefined();
    expect(() => parseGroupMap('{"qa":"qa"}')).toThrow(/group:default/);
    expect(() => parseGroupMap('{"qa":"group:default/shared","ops":"group:default/shared"}'))
      .toThrow(/ambiguous/);
  });

  it('never grants platform administration from a directory group name', () => {
    const user = {
      id: 'user-1',
      username: 'alice',
      displayName: 'Alice',
      email: 'alice@example.test',
      groups: ['group:default/platform'],
      source: 'oidc' as const,
      active: true,
    };

    expect(toSessionUser(user).isPlatformAdmin).toBe(false);
    expect(toSessionUser(user, true).isPlatformAdmin).toBe(true);
  });

  it('rejects an old authentication event during unlock', () => {
    const previous = new Date('2026-07-17T02:00:00.000Z');
    const started = new Date('2026-07-17T02:05:00.000Z');
    expect(() => assertFreshReauthentication(
      new Date('2026-07-17T02:05:01.000Z'),
      started,
      previous,
    )).not.toThrow();
    expect(() => assertFreshReauthentication(previous, started, previous)).toThrow(/fresh auth_time/);
  });
});
