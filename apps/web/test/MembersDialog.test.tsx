import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import { MembersDialog } from '../src/components/MembersDialog.tsx';
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
  return {
    id,
    vaultId: rootVaultId,
    subjectKind: 'user' as const,
    subjectId,
    role,
    createdAt: '2026-07-20T00:00:00.000Z',
  };
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
