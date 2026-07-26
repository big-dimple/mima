import { describe, expect, it } from 'vitest';
import { adGuidToString, ldapUserId } from '../../src/auth/ldap.ts';

describe('standalone authentication helpers', () => {
  it('normalizes Active Directory objectGUID byte order', () => {
    const raw = Buffer.from('33221100554477668899aabbccddeeff', 'hex');
    expect(adGuidToString(raw)).toBe('00112233-4455-6677-8899-aabbccddeeff');
  });

  it('derives stable local IDs from directory and GUID', () => {
    expect(ldapUserId('directory-a', '00112233-4455-6677-8899-aabbccddeeff')).toBe(
      ldapUserId('directory-a', '00112233-4455-6677-8899-aabbccddeeff'),
    );
    expect(ldapUserId('directory-a', 'guid')).not.toBe(ldapUserId('directory-b', 'guid'));
  });
});
