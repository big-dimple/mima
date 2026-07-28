import { act, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createMetaStore } from '@mima/client-core';
import type { AuditEvent } from '@mima/contracts';
import { AuditDialog } from '../src/components/AuditDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const firstVaultId = '10000000-0000-4000-8000-000000000001';
const secondVaultId = '10000000-0000-4000-8000-000000000002';

afterEach(() => useUi.getState().resetWorkspaceUi());

describe('AuditDialog', () => {
  it('keeps the latest vault response and explains known and future actions', async () => {
    const first = deferred<AuditEvent[]>();
    const second = deferred<AuditEvent[]>();
    const store = auditStore();
    const vaultAudit = vi.fn((vaultId: string) => (
      vaultId === firstVaultId ? first.promise : second.promise
    ));
    const services = { store, api: { vaultAudit } } as unknown as AppServices;
    useUi.getState().openAudit(firstVaultId);
    render(
      <AppContext.Provider value={services}>
        <AuditDialog />
      </AppContext.Provider>,
    );

    await waitFor(() => expect(vaultAudit).toHaveBeenCalledWith(firstVaultId));
    act(() => useUi.getState().openAudit(secondVaultId));
    await waitFor(() => expect(vaultAudit).toHaveBeenCalledWith(secondVaultId));
    second.resolve([
      auditEvent(2, 'item.e2ee.create'),
      auditEvent(3, 'future.atomic_action'),
    ]);

    expect(await screen.findByText('写入加密条目')).toBeVisible();
    expect(screen.getByText('其他系统操作（future.atomic_action）')).toBeVisible();
    expect(screen.getByRole('heading', { name: '审计日志 · 研发' })).toBeVisible();

    first.resolve([auditEvent(1, 'vault.delete')]);
    await waitFor(() => expect(screen.getByText('写入加密条目')).toBeVisible());
    expect(screen.queryByText('删除密码库')).not.toBeInTheDocument();
  });
});

function auditStore() {
  const store = createMetaStore();
  store.getState().applyDecryptedBootstrap({
    user: {
      id: 'u-owner', username: 'owner', displayName: 'Owner', email: 'owner@example.test', groups: [], isPlatformAdmin: false,
    },
    vaults: [
      teamVault(firstVaultId, '运维'),
      teamVault(secondVaultId, '研发'),
    ],
    memberships: [],
    items: [],
    cursor: 1,
    vaultCrypto: {},
    vaultDirectories: {},
    encryptedItems: {},
  });
  return store;
}

function teamVault(id: string, name: string) {
  return {
    id,
    kind: 'team' as const,
    name,
    ownerUserId: null,
    projectContext: { kind: 'root' as const },
    createdAt: '2026-07-20T00:00:00.000Z',
    updatedAt: '2026-07-20T00:00:00.000Z',
  };
}

function auditEvent(id: number, action: string): AuditEvent {
  return {
    id,
    ts: '2026-07-20T00:00:00.000Z',
    actorUserId: 'u-owner',
    action,
    success: true,
    details: {},
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
