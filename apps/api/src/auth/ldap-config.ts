import { env } from '../env.ts';
import type { LdapOptions } from './ldap.ts';

export function ldapOptionsFromEnv(): LdapOptions {
  return {
    directoryId: env.ldap.directoryId,
    urls: env.ldap.urls,
    bindDn: required(env.ldap.bindDn, 'MIMA_LDAP_BIND_DN'),
    bindPasswordFile: required(
      env.ldap.bindPasswordFile,
      'MIMA_LDAP_BIND_PASSWORD_FILE',
    ),
    baseDn: required(env.ldap.baseDn, 'MIMA_LDAP_BASE_DN'),
    userFilter: env.ldap.userFilter,
    loginAttribute: env.ldap.loginAttribute,
    stableIdAttribute: env.ldap.stableIdAttribute,
    displayNameAttribute: env.ldap.displayNameAttribute,
    emailAttribute: env.ldap.emailAttribute,
    caFile: env.ldap.caFile,
    connectTimeoutMs: env.ldap.connectTimeoutMs,
    operationTimeoutMs: env.ldap.operationTimeoutMs,
    syncIntervalMs: env.ldap.syncIntervalMs,
    maxStaleMs: env.ldap.maxStaleMs,
    pageSize: env.ldap.pageSize,
    maxDropPercent: env.ldap.maxDropPercent,
  };
}

function required(value: string | undefined, name: string): string {
  if (!value) throw new Error(`${name} is required when LDAP is configured`);
  return value;
}
