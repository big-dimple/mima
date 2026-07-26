import { randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { FileMasterKeyProvider, encryptSecret } from '@mima/crypto';
import type { ItemKind, MembershipRole, Sensitivity, SubjectKind } from '@mima/contracts';
import { createDb, createPool } from './client.ts';
import { runMigrations } from './migrate.ts';
import { items, itemSecretVersions, users, vaultMemberships, vaults } from './schema.ts';
import { DEV_USERS } from '../auth/provider.ts';
import { env } from '../env.ts';
import { legacyEnv } from '../legacy-env.ts';

interface SeedItem {
  kind: ItemKind;
  title: string;
  username: string | null;
  origin: string | null;
  tags: string[];
  favorite?: boolean;
  sensitivity?: Sensitivity;
  /** 演示用假敏感内容（example.test 数据），加密后入库，明文不落任何地方。 */
  secretValue: string;
}

export async function seed(databaseUrl = env.databaseUrl): Promise<void> {
  await runMigrations(databaseUrl);
  const pool = createPool(databaseUrl);
  const db = createDb(pool);
  const keys = new FileMasterKeyProvider(legacyEnv.masterKeyDir);

  try {
    for (const u of DEV_USERS) {
      await db
        .insert(users)
        .values({ id: u.id, username: u.username, displayName: u.displayName, email: u.email, groups: u.groups })
        .onConflictDoUpdate({
          target: users.id,
          set: { username: u.username, displayName: u.displayName, email: u.email, groups: u.groups },
        });
      await db
        .insert(vaults)
        .values({ kind: 'personal', name: '个人库', ownerUserId: u.id })
        .onConflictDoNothing();
    }

    const existingTeams = await db.select().from(vaults).where(eq(vaults.kind, 'team'));
    if (existingTeams.length > 0) {
      console.log('team vaults already seeded, skipping');
      return;
    }

    const opsVault = (await db.insert(vaults).values({ kind: 'team', name: 'Ops 共享库' }).returning())[0]!;
    const qaVault = (await db.insert(vaults).values({ kind: 'team', name: 'QA 工具库' }).returning())[0]!;

    const memberships: {
      vaultId: string;
      subjectKind: Exclude<SubjectKind, 'custom_group'>;
      subjectId: string;
      role: MembershipRole;
    }[] = [
      { vaultId: opsVault.id, subjectKind: 'user', subjectId: 'u-bob', role: 'owner' },
      { vaultId: opsVault.id, subjectKind: 'group', subjectId: 'group:default/ops', role: 'editor' },
      { vaultId: opsVault.id, subjectKind: 'group', subjectId: 'group:default/qa', role: 'viewer' },
      // erin 通过 qa 组是 viewer，但直接角色 auditor 覆盖组角色 → 不能 Reveal
      { vaultId: opsVault.id, subjectKind: 'user', subjectId: 'u-erin', role: 'auditor' },
      { vaultId: qaVault.id, subjectKind: 'user', subjectId: 'u-carol', role: 'owner' },
      { vaultId: qaVault.id, subjectKind: 'group', subjectId: 'group:default/rd', role: 'viewer' },
    ];
    await db.insert(vaultMemberships).values(memberships);

    const personalBob = (await db.select().from(vaults).where(eq(vaults.ownerUserId, 'u-bob')))[0]!;

    const seedItems: { vaultId: string; item: SeedItem }[] = [
      {
        vaultId: opsVault.id,
        item: {
          kind: 'login', title: '内部部署平台', username: 'deploy-bot',
          origin: 'https://deploy.example.test', tags: ['ops', '部署'], favorite: true,
          sensitivity: 'high', secretValue: 'seed-pass-deploy-001',
        },
      },
      {
        vaultId: opsVault.id,
        item: {
          kind: 'api_token', title: 'CI 发布 Token', username: 'ci-release',
          origin: null, tags: ['ci'], sensitivity: 'high', secretValue: 'seed-token-ci-001',
        },
      },
      {
        vaultId: opsVault.id,
        item: {
          kind: 'secure_note', title: '值班手册摘要', username: null,
          origin: null, tags: ['runbook'], sensitivity: 'low',
          secretValue: '值班时优先查看 runbook.example.test；升级路径联系 ops 频道。',
        },
      },
      {
        vaultId: qaVault.id,
        item: {
          kind: 'login', title: '测试环境网关', username: 'qa-bot',
          origin: 'https://qa-gateway.example.test', tags: ['qa'], sensitivity: 'medium',
          secretValue: 'seed-pass-qa-001',
        },
      },
      {
        vaultId: personalBob.id,
        item: {
          kind: 'login', title: '本地演示登录', username: 'demo-user',
          origin: 'http://localhost:4173', tags: ['演示'], sensitivity: 'low',
          secretValue: 'seed-pass-demo-fill',
        },
      },
    ];

    for (const { vaultId, item } of seedItems) {
      const itemId = randomUUID();
      const enc = encryptSecret(keys, { vaultId, itemId, secretVersion: 1, itemKind: item.kind }, item.secretValue);
      await db.insert(items).values({
        id: itemId,
        vaultId,
        kind: item.kind,
        title: item.title,
        username: item.username,
        origin: item.origin,
        tags: item.tags,
        favorite: item.favorite ?? false,
        sensitivity: item.sensitivity ?? 'medium',
        updatedBy: 'seed',
      });
      await db.insert(itemSecretVersions).values({
        itemId,
        vaultId,
        itemKind: item.kind,
        secretVersion: 1,
        ciphertext: enc.ciphertext,
        iv: enc.iv,
        authTag: enc.authTag,
        wrappedDek: enc.wrappedDek,
        keyVersion: enc.keyVersion,
        createdBy: 'seed',
      });
    }
    console.log('seed complete: 2 team vaults, 5 items, 5 users');
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && process.argv[1].endsWith('seed.ts')) {
  seed().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
