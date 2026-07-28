import * as Tooltip from '@radix-ui/react-tooltip';
import { act, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import { MembersDialog } from '../src/components/MembersDialog.tsx';
import { ConfirmDialog } from '../src/components/ConfirmDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const rootVaultId = '10000000-0000-4000-8000-000000000001';
const firstProjectId = '10000000-0000-4000-8000-000000000002';
const secondProjectId = '10000000-0000-4000-8000-000000000003';

afterEach(() => {
  useUi.setState({ membersDialogVaultId: null, toasts: [] });
});

describe('MembersDialog project grants', () => {
  it('shows pending access as plain-language status and keeps non-actions out of buttons', async () => {
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-owner',
        username: 'owner',
        displayName: 'Owner',
        email: 'owner@example.test',
        groups: [],
        isPlatformAdmin: false,
      },
      vaults: [teamVault(rootVaultId, '运维', { kind: 'root' })],
      memberships: [
        membership('membership-owner', 'u-owner', 'owner'),
        membership('membership-carol', 'u-carol', 'viewer'),
        membership('membership-dave', 'u-dave', 'viewer'),
      ],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });
    const carolTask = envelopeTask('task-carol', 'u-carol', true);
    const daveTask = envelopeTask('task-dave', 'u-dave', false);
    const listEnvelopeTasks = vi.fn()
      .mockResolvedValueOnce([carolTask, daveTask])
      .mockResolvedValue([daveTask]);
    const completeEnvelopeTask = vi.fn(async () => undefined);
    const services = {
      store,
      api: {
        searchUsers: vi.fn(async () => ({
          syncedAt: null,
          users: [
            { id: 'u-owner', username: 'owner', displayName: 'Owner' },
            { id: 'u-carol', username: 'carol', displayName: 'Carol' },
            { id: 'u-dave', username: 'dave', displayName: 'Dave' },
          ],
        })),
        groups: vi.fn(async () => []),
      },
      zeroKnowledge: {
        listEnvelopeTasks,
        getVaultOwnershipTransfer: vi.fn(async () => null),
        completeEnvelopeTask,
      },
    } as unknown as AppServices;
    useUi.getState().openMembers(rootVaultId);

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <MembersDialog />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(await screen.findByText('这些同事已经获得权限，但还打不开当前密码库。由你在此开通即可，不需要对方领取文件。')).toBeVisible();
    expect(await screen.findByRole('row', { name: /Carol.*1 项待开通/ })).toBeVisible();
    expect(await screen.findByRole('row', { name: /Dave.*等待对方设置主密码/ })).toBeVisible();
    expect(screen.queryByRole('button', { name: '等待对方设置主密码' })).not.toBeInTheDocument();
    expect(screen.getAllByText('等待对方设置主密码').some((node) => node.tagName === 'SPAN')).toBe(true);
    expect(screen.getAllByRole('button', { name: '开通', exact: true })).toHaveLength(1);

    await userEvent.click(screen.getByRole('button', { name: '开通', exact: true }));
    await waitFor(() => expect(completeEnvelopeTask).toHaveBeenCalledWith(carolTask));
    expect(await screen.findByRole('row', { name: /Carol.*已开通/ })).toBeVisible();
  });

  it('keeps successful projects and retries only failed grants', async () => {
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-owner',
        username: 'owner',
        displayName: 'Owner',
        email: 'owner@example.test',
        groups: [],
        isPlatformAdmin: false,
      },
      vaults: [
        teamVault(rootVaultId, '运维', { kind: 'root' }),
        teamVault(firstProjectId, '云平台项目', {
          kind: 'project',
          visibleParentVaultId: rootVaultId,
        }),
        teamVault(secondProjectId, '示例云项目', {
          kind: 'project',
          visibleParentVaultId: rootVaultId,
        }),
      ],
      memberships: [{
        id: '30000000-0000-4000-8000-000000000001',
        vaultId: rootVaultId,
        subjectKind: 'user',
        subjectId: 'u-owner',
        role: 'owner',
        createdAt: '2026-07-20T00:00:00.000Z',
      }],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });
    let secondProjectFails = true;
    const setVaultMembership = vi.fn(async (vaultId: string) => {
      if (vaultId === secondProjectId && secondProjectFails) {
        throw new Error('该项目由其他拥有者管理');
      }
      return {
        ok: true as const,
        accessGeneration: 2,
        rekeyRequired: false,
        retainedAccess: true,
        rekeyTask: null,
        envelopeTasks: null,
      };
    });
    const refresh = vi.fn(async () => undefined);
    const searchUsers = vi.fn(async (_query: string, includeIds: string[] = []) => ({
      syncedAt: null,
      users: includeIds.includes('u-owner')
        ? [{ id: 'u-owner', username: 'owner', displayName: 'Owner' }]
        : [{ id: 'u-member', username: 'erin', displayName: 'Erin' }],
    }));
    const services = {
      store,
      api: {
        searchUsers,
        groups: vi.fn(async () => []),
      },
      zeroKnowledge: {
        listEnvelopeTasks: vi.fn(async () => []),
        getVaultOwnershipTransfer: vi.fn(async () => null),
        setVaultMembership,
        refresh,
      },
    } as unknown as AppServices;
    useUi.getState().openMembers(rootVaultId);

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <MembersDialog />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    const picker = await screen.findByRole('combobox', { name: '批量授权用户' });
    await userEvent.type(picker, 'erin');
    await userEvent.click(await screen.findByRole('option', { name: /Erin/ }));
    await userEvent.click(screen.getByRole('button', { name: '开始授权' }));

    await waitFor(() => expect(setVaultMembership).toHaveBeenCalledTimes(2));
    expect(setVaultMembership).toHaveBeenCalledWith(
      firstProjectId,
      'user',
      'u-member',
      'viewer',
      'grant_or_upgrade',
      false,
    );
    expect(await screen.findByText('该项目由其他拥有者管理')).toBeVisible();
    expect(screen.getByText('授权完成')).toBeVisible();

    secondProjectFails = false;
    await userEvent.click(screen.getByRole('button', { name: '仅重试失败项' }));

    await waitFor(() => expect(setVaultMembership).toHaveBeenCalledTimes(3));
    expect(setVaultMembership.mock.calls.filter(([vaultId]) => vaultId === firstProjectId)).toHaveLength(1);
    expect(setVaultMembership.mock.calls.filter(([vaultId]) => vaultId === secondProjectId)).toHaveLength(2);
    await waitFor(() => expect(screen.queryByText('该项目由其他拥有者管理')).not.toBeInTheDocument());
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it('confirms the exact member and keeps the dialog open when removing access', async () => {
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-owner', username: 'owner', displayName: 'Owner', email: 'owner@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [teamVault(rootVaultId, '运维', { kind: 'root' })],
      memberships: [
        membership('membership-owner', 'u-owner', 'owner'),
        membership('membership-carol', 'u-carol', 'viewer'),
      ],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });
    const removeVaultMembership = vi.fn().mockResolvedValue({
      ok: true,
      rekeyRequired: false,
      retainedAccess: false,
      accessGeneration: 2,
      rekeyTask: null,
      envelopeTasks: null,
    });
    const services = {
      store,
      api: {
        searchUsers: vi.fn().mockResolvedValue({
          syncedAt: null,
          users: [
            { id: 'u-owner', username: 'owner', displayName: 'Owner' },
            { id: 'u-carol', username: 'carol', displayName: 'Carol' },
          ],
        }),
        groups: vi.fn().mockResolvedValue([]),
      },
      zeroKnowledge: {
        listEnvelopeTasks: vi.fn().mockResolvedValue([]),
        getVaultOwnershipTransfer: vi.fn().mockResolvedValue(null),
        removeVaultMembership,
      },
    } as unknown as AppServices;
    useUi.getState().openMembers(rootVaultId);
    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <MembersDialog />
          <ConfirmDialog />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    const remove = await screen.findByRole('button', { name: '移除授权' });
    await userEvent.click(remove);
    expect(screen.getByText(/将移除 Carol 的“查看”授权/)).toBeVisible();
    expect(removeVaultMembership).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: '保留授权' }));
    expect(removeVaultMembership).not.toHaveBeenCalled();

    await userEvent.click(remove);
    await userEvent.click(screen.getByRole('button', { name: '确认移除' }));
    await waitFor(() => expect(removeVaultMembership).toHaveBeenCalledWith(rootVaultId, 'user', 'u-carol'));
    expect(screen.getByRole('heading', { name: '成员管理 · 运维' })).toBeVisible();
  });

  it('ignores an old ownership response after switching to another vault', async () => {
    const secondVaultId = '10000000-0000-4000-8000-000000000004';
    const firstTransfer = deferred<ReturnType<typeof ownershipTransfer>>();
    const secondTransfer = deferred<ReturnType<typeof ownershipTransfer>>();
    const store = createMetaStore();
    store.getState().applyDecryptedBootstrap({
      user: {
        id: 'u-owner', username: 'owner', displayName: 'Owner', email: 'owner@example.test', groups: [], isPlatformAdmin: false,
      },
      vaults: [
        teamVault(rootVaultId, '运维', { kind: 'root' }),
        teamVault(secondVaultId, '研发', { kind: 'root' }),
      ],
      memberships: [
        membershipFor(rootVaultId, 'membership-a-owner', 'u-owner', 'owner'),
        membershipFor(rootVaultId, 'membership-a-target', 'u-a-target', 'viewer'),
        membershipFor(secondVaultId, 'membership-b-owner', 'u-owner', 'owner'),
        membershipFor(secondVaultId, 'membership-b-target', 'u-b-target', 'viewer'),
      ],
      items: [],
      cursor: 1,
      vaultCrypto: {},
      vaultDirectories: {},
      encryptedItems: {},
    });
    const getVaultOwnershipTransfer = vi.fn((vaultId: string) => (
      vaultId === rootVaultId ? firstTransfer.promise : secondTransfer.promise
    ));
    const services = {
      store,
      api: {
        searchUsers: vi.fn().mockResolvedValue({
          syncedAt: null,
          users: [
            { id: 'u-owner', username: 'owner', displayName: 'Owner' },
            { id: 'u-a-target', username: 'a', displayName: 'ATarget' },
            { id: 'u-b-target', username: 'b', displayName: 'BTarget' },
          ],
        }),
        groups: vi.fn().mockResolvedValue([]),
      },
      zeroKnowledge: {
        listEnvelopeTasks: vi.fn().mockResolvedValue([]),
        getVaultOwnershipTransfer,
      },
    } as unknown as AppServices;
    useUi.getState().openMembers(rootVaultId);
    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider><MembersDialog /></Tooltip.Provider>
      </AppContext.Provider>,
    );

    await waitFor(() => expect(getVaultOwnershipTransfer).toHaveBeenCalledWith(rootVaultId));
    act(() => useUi.getState().openMembers(secondVaultId));
    await waitFor(() => expect(getVaultOwnershipTransfer).toHaveBeenCalledWith(secondVaultId));
    secondTransfer.resolve(ownershipTransfer(secondVaultId, 'u-b-target'));
    expect(await screen.findByText(/等待 BTarget/)).toBeVisible();

    firstTransfer.resolve(ownershipTransfer(rootVaultId, 'u-a-target'));
    await waitFor(() => expect(screen.getByText(/等待 BTarget/)).toBeVisible());
    expect(screen.queryByText(/等待 ATarget/)).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: '成员管理 · 研发' })).toBeVisible();
  });
});

function teamVault(
  id: string,
  name: string,
  projectContext:
    | { kind: 'root' }
    | { kind: 'project'; visibleParentVaultId: string | null },
) {
  return {
    id,
    kind: 'team' as const,
    name,
    ownerUserId: null,
    projectContext,
    createdAt: '2026-07-20T00:00:00.000Z',
    updatedAt: '2026-07-20T00:00:00.000Z',
  };
}

function membership(id: string, subjectId: string, role: 'owner' | 'viewer') {
  return membershipFor(rootVaultId, id, subjectId, role);
}

function membershipFor(vaultId: string, id: string, subjectId: string, role: 'owner' | 'viewer') {
  return {
    id,
    vaultId,
    subjectKind: 'user' as const,
    subjectId,
    role,
    createdAt: '2026-07-20T00:00:00.000Z',
  };
}

function ownershipTransfer(vaultId: string, toOwnerUserId: string) {
  return {
    id: crypto.randomUUID(),
    vaultId,
    fromOwnerUserId: 'u-owner',
    toOwnerUserId,
    envelopeTaskId: crypto.randomUUID(),
    keyEpoch: 1,
    envelopeReady: true,
    completedEnvelopeId: null,
    envelopeCiphertextDigest: null,
    keyPossessionProofAvailable: true,
    expectedAccessGeneration: 1,
    status: 'pending' as const,
    acceptanceRequired: true,
    acceptanceStatus: 'waiting' as const,
    acceptedByDeviceId: null,
    acceptanceDigest: null,
    acceptanceSignature: null,
    acceptedAt: null,
    rekeyTask: null,
    createdAt: '2026-07-20T00:00:00.000Z',
    updatedAt: '2026-07-20T00:00:00.000Z',
    completedAt: null,
    cancelledAt: null,
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function envelopeTask(id: string, recipientUserId: string, ready: boolean) {
  return {
    id,
    vaultId: rootVaultId,
    keyEpoch: 1,
    authorizationKind: 'direct' as const,
    authorizationRef: recipientUserId,
    recipientUserId,
    capability: 'full' as const,
    expectedProfileGeneration: ready ? 1 : null,
    status: 'pending' as const,
    completedEnvelopeId: null,
    recipientProfile: ready ? {
      keyVersion: 1,
      encryptionPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      signingPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    } : null,
    createdAt: '2026-07-20T00:00:00.000Z',
    updatedAt: '2026-07-20T00:00:00.000Z',
    completedAt: null,
    cancelledAt: null,
  };
}
