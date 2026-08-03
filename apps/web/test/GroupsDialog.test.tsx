import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { CustomGroup, CustomGroupDetail } from '@mima/contracts';
import { ApiRequestError } from '@mima/client-core';
import { GroupsDialog } from '../src/components/GroupsDialog.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';

const group: CustomGroup = {
  id: '10000000-0000-4000-8000-000000000001',
  name: '研发组',
  ownerUserId: 'user-1',
  ownerDisplayName: 'Bob Li',
  memberCount: 1,
  pendingEnvelopeCount: 0,
  isOwner: true,
  isMember: false,
  frozen: false,
  createdAt: '2026-07-20T00:00:00.000Z',
  updatedAt: '2026-07-20T00:00:00.000Z',
};

const secondGroup: CustomGroup = {
  ...group,
  id: '10000000-0000-4000-8000-000000000002',
  name: '运营组',
};

const detail: CustomGroupDetail = {
  ...group,
  revision: 'revision-development-group-001',
  members: [{ id: 'user-2', username: 'carol', displayName: 'Carol' }],
};

const secondDetail: CustomGroupDetail = {
  ...secondGroup,
  revision: 'revision-operations-group-001',
  members: [{ id: 'user-3', username: 'dave', displayName: 'Dave' }],
};

describe('GroupsDialog', () => {
  beforeEach(() => {
    useUi.getState().resetWorkspaceUi();
    useUi.setState({ groupsOpen: true, toasts: [] });
  });

  afterEach(() => useUi.getState().resetWorkspaceUi());

  it('keeps the header and working area as stable dialog rows', async () => {
    const api = {
      groups: vi.fn().mockResolvedValue([group]),
      group: vi.fn().mockResolvedValue(detail),
    };
    renderDialog(api);

    await screen.findByLabelText('名称');
    const header = screen.getByTestId('groups-dialog-header');
    const layout = screen.getByTestId('groups-dialog-layout');
    expect(header.parentElement).toBe(layout.parentElement);
    expect(header.compareDocumentPosition(layout) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it('shows only member counts and keeps envelope delivery internal', async () => {
    const pendingGroup = { ...group, memberCount: 4, pendingEnvelopeCount: 2 };
    const api = {
      groups: vi.fn().mockResolvedValue([pendingGroup]),
      group: vi.fn().mockResolvedValue({ ...detail, ...pendingGroup }),
    };
    renderDialog(api);

    expect(await screen.findByText('4 人')).toBeVisible();
    expect(screen.queryByText(/待开通/)).not.toBeInTheDocument();
    expect(screen.queryByTestId('group-status-help')).not.toBeInTheDocument();
  });

  it('moves selection with filtered results and clears stale details', async () => {
    const api = {
      groups: vi.fn(async (_scope: string, query: string) => {
        if (query === '运营') return [secondGroup];
        if (query === '不存在') return [];
        return [group, secondGroup];
      }),
      group: vi.fn(async (groupId: string) => groupId === group.id ? detail : secondDetail),
    };
    renderDialog(api);

    await screen.findByRole('heading', { name: '研发组' });
    const search = screen.getByRole('textbox', { name: '搜索用户组' });
    await userEvent.type(search, '运营');
    await screen.findByRole('heading', { name: '运营组' });
    expect(screen.queryByRole('heading', { name: '研发组' })).not.toBeInTheDocument();

    await userEvent.clear(search);
    await userEvent.type(search, '不存在');
    await screen.findByText('暂无用户组');
    await waitFor(() => expect(screen.queryByRole('heading', { name: '运营组' })).not.toBeInTheDocument());
  });

  it('restores an edit draft and returns from create to the prior group', async () => {
    const api = {
      groups: vi.fn().mockResolvedValue([group]),
      group: vi.fn().mockResolvedValue(detail),
    };
    renderDialog(api);

    const name = await screen.findByLabelText('名称');
    await userEvent.clear(name);
    await userEvent.type(name, '未保存名称');
    await userEvent.click(screen.getByRole('button', { name: '取消' }));
    expect(name).toHaveValue('研发组');

    await userEvent.click(screen.getByRole('button', { name: '新建用户组' }));
    const createName = screen.getByLabelText('名称');
    await userEvent.type(createName, '临时用户组');
    await userEvent.click(screen.getByRole('button', { name: '取消' }));
    await waitFor(() => expect(screen.getByRole('heading', { name: '研发组' })).toBeVisible());
  });

  it('keeps only the latest detail response during rapid selection', async () => {
    const first = deferred<CustomGroupDetail>();
    const second = deferred<CustomGroupDetail>();
    const api = {
      groups: vi.fn().mockResolvedValue([group, secondGroup]),
      group: vi.fn((groupId: string) => groupId === group.id ? first.promise : second.promise),
    };
    renderDialog(api);

    await screen.findByRole('button', { name: /运营组/ });
    await waitFor(() => expect(api.group).toHaveBeenCalledWith(group.id));
    await userEvent.click(screen.getByRole('button', { name: /运营组/ }));
    await waitFor(() => expect(api.group).toHaveBeenCalledWith(secondGroup.id));

    second.resolve(secondDetail);
    await screen.findByRole('heading', { name: '运营组' });
    first.resolve(detail);
    await waitFor(() => expect(screen.getByRole('heading', { name: '运营组' })).toBeVisible());
    expect(screen.queryByRole('heading', { name: '研发组' })).not.toBeInTheDocument();
    expect(api.groups).toHaveBeenCalledTimes(1);
  });

  it('saves name and members with one revision-checked request', async () => {
    const updated = { ...detail, name: '研发平台组', revision: 'revision-development-group-002' };
    const api = {
      groups: vi.fn().mockResolvedValue([group]),
      group: vi.fn().mockResolvedValue(detail),
      updateGroup: vi.fn().mockResolvedValue(updated),
    };
    renderDialog(api);

    const name = await screen.findByLabelText('名称');
    await userEvent.clear(name);
    await userEvent.type(name, '研发平台组');
    await userEvent.click(screen.getByRole('button', { name: '保存' }));

    await waitFor(() => expect(api.updateGroup).toHaveBeenCalledWith(
      group.id,
      detail.revision,
      '研发平台组',
      ['user-2'],
      expect.any(String),
    ));
    expect(await screen.findByRole('heading', { name: '研发平台组' })).toBeVisible();
  });

  it('preserves the local draft and explains a concurrent update', async () => {
    const api = {
      groups: vi.fn().mockResolvedValue([group]),
      group: vi.fn().mockResolvedValue(detail),
      updateGroup: vi.fn().mockRejectedValue(new ApiRequestError(409, {
        statusCode: 409,
        error: 'Conflict',
        code: 'group_version_conflict',
        message: 'conflict',
      })),
    };
    renderDialog(api);

    const name = await screen.findByLabelText('名称');
    await userEvent.clear(name);
    await userEvent.type(name, '本地未保存名称');
    await userEvent.click(screen.getByRole('button', { name: '保存' }));

    expect(await screen.findByRole('alert')).toHaveTextContent('你的修改尚未丢失');
    expect(name).toHaveValue('本地未保存名称');
    expect(screen.getByRole('button', { name: '加载最新内容' })).toBeVisible();
  });

  it('does not let background search replace a group with an unsaved draft', async () => {
    const api = {
      groups: vi.fn().mockResolvedValue([group, secondGroup]),
      group: vi.fn(async (groupId: string) => groupId === group.id ? detail : secondDetail),
    };
    renderDialog(api);

    const name = await screen.findByLabelText('名称');
    await userEvent.clear(name);
    await userEvent.type(name, '尚未保存的研发组');

    const search = screen.getByRole('textbox', { name: '搜索用户组' });
    expect(search).toBeDisabled();
    expect(search).toHaveAttribute('placeholder', '请先保存或取消当前修改');
    expect(screen.getByRole('heading', { name: '研发组' })).toBeVisible();
    expect(name).toHaveValue('尚未保存的研发组');
  });
});

function renderDialog(api: Record<string, unknown>) {
  render(
    <AppContext.Provider value={{ api } as unknown as AppServices}>
      <Tooltip.Provider>
        <GroupsDialog />
      </Tooltip.Provider>
    </AppContext.Provider>,
  );
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
