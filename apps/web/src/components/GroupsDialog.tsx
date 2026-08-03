import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { AlertCircle, Plus, Search, Trash2, X } from 'lucide-react';
import type { CustomGroup, CustomGroupDetail, UserSearchResult } from '@mima/contracts';
import { ApiRequestError } from '@mima/client-core';
import { useApp } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ActionButton } from './ActionButton.tsx';
import { IconButton } from './IconButton.tsx';
import { UserMultiPicker, UserPicker } from './UserPicker.tsx';
import { EmptyState, LoadingState } from './AsyncState.tsx';
import dialogStyles from './dialog.module.css';
import styles from './GroupsDialog.module.css';

export function GroupsDialog() {
  const { api } = useApp();
  const open = useUi((state) => state.groupsOpen);
  const setOpen = useUi((state) => state.setGroupsOpen);
  const toast = useUi((state) => state.toast);
  const [scope, setScope] = useState<'owned' | 'joined'>('owned');
  const [query, setQuery] = useState('');
  const [groups, setGroups] = useState<CustomGroup[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<CustomGroupDetail | null>(null);
  const [listLoading, setListLoading] = useState(false);
  const [listError, setListError] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState(false);
  const [creating, setCreating] = useState(false);
  const [draftName, setDraftName] = useState('');
  const [draftMembers, setDraftMembers] = useState<UserSearchResult[]>([]);
  const [transferTo, setTransferTo] = useState('');
  const [saving, setSaving] = useState(false);
  const [conflictMessage, setConflictMessage] = useState<string | null>(null);
  const listRequestRef = useRef(0);
  const detailRequestRef = useRef(0);
  const dirtyRef = useRef(false);
  const mainRef = useRef<HTMLElement>(null);

  const dirty = useMemo(() => {
    if (creating) return Boolean(draftName.trim() || draftMembers.length > 0);
    if (!detail?.isOwner) return false;
    return draftName.trim() !== detail.name ||
      !sameMemberIds(draftMembers.map((member) => member.id), detail.members.map((member) => member.id));
  }, [creating, detail, draftMembers, draftName]);
  dirtyRef.current = dirty;

  const loadGroups = useCallback(async () => {
    const requestId = ++listRequestRef.current;
    setListLoading(true);
    setListError(false);
    try {
      const rows = await api.groups(scope, query);
      if (requestId !== listRequestRef.current) return;
      setGroups(rows);
      setSelectedId((current) => (
        dirtyRef.current || (current && rows.some((row) => row.id === current))
          ? current
          : rows[0]?.id ?? null
      ));
    } catch {
      if (requestId === listRequestRef.current) setListError(true);
    } finally {
      if (requestId === listRequestRef.current) setListLoading(false);
    }
  }, [api, query, scope]);

  const loadDetail = useCallback(async (groupId: string) => {
    const requestId = ++detailRequestRef.current;
    setDetailLoading(true);
    setDetailError(false);
    setConflictMessage(null);
    setDetail(null);
    if (mainRef.current) mainRef.current.scrollTop = 0;
    try {
      const value = await api.group(groupId);
      if (requestId !== detailRequestRef.current) return;
      setDetail(value);
      setDraftName(value.name);
      setDraftMembers(value.members);
      setTransferTo('');
    } catch {
      if (requestId === detailRequestRef.current) setDetailError(true);
    } finally {
      if (requestId === detailRequestRef.current) setDetailLoading(false);
    }
  }, [api]);

  useEffect(() => {
    if (!open) return;
    listRequestRef.current += 1;
    const timer = window.setTimeout(() => void loadGroups(), 300);
    return () => window.clearTimeout(timer);
  }, [loadGroups, open]);

  useEffect(() => {
    if (!open || creating) return;
    if (!selectedId) {
      detailRequestRef.current += 1;
      setDetail(null);
      setDetailLoading(false);
      setDetailError(false);
      return;
    }
    void loadDetail(selectedId);
  }, [creating, loadDetail, open, selectedId]);

  if (!open) return null;

  const confirmDiscard = async (): Promise<boolean> => {
    if (!dirty) return true;
    return useUi.getState().requestConfirm({
      title: '放弃未保存修改？',
      body: '当前用户组还有未保存的名称或成员调整。放弃后无法恢复。',
      confirmText: '放弃修改',
      cancelText: '继续编辑',
      danger: true,
    });
  };

  const switchScope = async (nextScope: 'owned' | 'joined') => {
    if (scope === nextScope || !(await confirmDiscard())) return;
    detailRequestRef.current += 1;
    setScope(nextScope);
    setGroups([]);
    setSelectedId(null);
    setDetail(null);
    setCreating(false);
    setConflictMessage(null);
  };

  const selectGroup = async (groupId: string) => {
    if ((!creating && selectedId === groupId) || !(await confirmDiscard())) return;
    detailRequestRef.current += 1;
    setCreating(false);
    setSelectedId(groupId);
  };

  const beginCreate = async () => {
    if (!(await confirmDiscard())) return;
    detailRequestRef.current += 1;
    setCreating(true);
    setDraftName('');
    setDraftMembers([]);
    setConflictMessage(null);
    if (mainRef.current) mainRef.current.scrollTop = 0;
  };

  const cancelEdit = () => {
    setConflictMessage(null);
    if (creating) {
      setCreating(false);
      setDraftName(detail?.name ?? '');
      setDraftMembers(detail?.members ?? []);
      return;
    }
    if (!detail) return;
    setDraftName(detail.name);
    setDraftMembers(detail.members);
  };

  const reportMutationError = (caught: unknown, fallback: string) => {
    if (caught instanceof ApiRequestError && caught.status === 409 && caught.body.code === 'group_version_conflict') {
      setConflictMessage('另一位同事已更新这个用户组。你的修改尚未丢失，请加载最新内容后重新确认。');
      return;
    }
    toast('error', caught instanceof Error ? caught.message : fallback);
  };

  const save = async () => {
    const name = draftName.trim();
    if (!name) return;
    setSaving(true);
    setConflictMessage(null);
    try {
      if (creating) {
        const created = await api.createGroup(
          name,
          draftMembers.map((member) => member.id),
          crypto.randomUUID(),
        );
        setCreating(false);
        setSelectedId(created.id);
        setDetail(created);
        setDraftName(created.name);
        setDraftMembers(created.members);
        setGroups((current) => sortGroups([...current.filter((row) => row.id !== created.id), groupSummary(created)]));
        toast('info', '用户组已创建');
      } else if (detail?.isOwner) {
        const updated = await api.updateGroup(
          detail.id,
          detail.revision,
          name,
          draftMembers.map((member) => member.id),
          crypto.randomUUID(),
        );
        setDetail(updated);
        setDraftName(updated.name);
        setDraftMembers(updated.members);
        setGroups((current) => sortGroups(current.map((row) => row.id === updated.id ? groupSummary(updated) : row)));
        toast('info', '用户组已更新');
      }
      void loadGroups();
    } catch (caught) {
      reportMutationError(caught, '保存失败');
    } finally {
      setSaving(false);
    }
  };

  const transfer = async () => {
    if (!detail || !transferTo || dirty) return;
    const confirmed = await useUi.getState().requestConfirm({
      title: '转移用户组',
      body: `确定转移「${detail.name}」的管理权？`,
      confirmText: '转移',
      danger: true,
    });
    if (!confirmed) return;
    setSaving(true);
    try {
      await api.transferGroup(detail.id, detail.revision, transferTo, crypto.randomUUID());
      toast('info', '用户组拥有者已变更');
      removeSelectedGroup(detail.id);
      void loadGroups();
    } catch (caught) {
      reportMutationError(caught, '转移失败');
    } finally {
      setSaving(false);
    }
  };

  const remove = async () => {
    if (!detail || dirty) return;
    const confirmed = await useUi.getState().requestConfirm({
      title: '删除用户组',
      body: `确定删除「${detail.name}」？`,
      confirmText: '删除',
      danger: true,
    });
    if (!confirmed) return;
    setSaving(true);
    try {
      await api.deleteGroup(detail.id, detail.revision, crypto.randomUUID());
      toast('info', '用户组已删除');
      removeSelectedGroup(detail.id);
      void loadGroups();
    } catch (caught) {
      reportMutationError(caught, '删除失败');
    } finally {
      setSaving(false);
    }
  };

  const removeSelectedGroup = (groupId: string) => {
    const index = groups.findIndex((group) => group.id === groupId);
    const remaining = groups.filter((group) => group.id !== groupId);
    const fallback = remaining[Math.min(Math.max(index, 0), remaining.length - 1)]?.id ?? null;
    detailRequestRef.current += 1;
    setGroups(remaining);
    setSelectedId(fallback);
    setDetail(null);
    setConflictMessage(null);
  };

  const loadLatest = async () => {
    if (!selectedId) return;
    if (dirty) {
      const confirmed = await useUi.getState().requestConfirm({
        title: '加载最新内容？',
        body: '加载后会用同事保存的最新内容替换当前草稿。',
        confirmText: '加载最新内容',
        cancelText: '保留当前草稿',
        danger: true,
      });
      if (!confirmed) return;
    }
    await loadDetail(selectedId);
  };

  const requestClose = async () => {
    if (saving || !(await confirmDiscard())) return;
    setOpen(false);
  };

  return (
    <Dialog.Root open onOpenChange={(nextOpen) => {
      if (!nextOpen) void requestClose();
    }}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={`${dialogStyles.content} ${styles.content}`}>
          <div className={styles.header} data-testid="groups-dialog-header">
            <Dialog.Title className={dialogStyles.title}>管理用户组</Dialog.Title>
            <Dialog.Description className={dialogStyles.description}>
              创建用于团队密码库授权的用户组
            </Dialog.Description>
          </div>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭" disabled={saving}><X size={16} /></button>
          </Dialog.Close>

          <div className={styles.layout} data-testid="groups-dialog-layout">
            <aside className={styles.sidebar} aria-busy={listLoading}>
              <div className={styles.tabs} aria-label="用户组视图">
                <button className={scope === 'owned' ? styles.tabActive : ''} onClick={() => void switchScope('owned')}>我管理的</button>
                <button className={scope === 'joined' ? styles.tabActive : ''} onClick={() => void switchScope('joined')}>我加入的</button>
              </div>
              <div className={styles.search}>
                <Search size={14} aria-hidden />
                <input
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                  aria-label="搜索用户组"
                  placeholder={dirty ? '请先保存或取消当前修改' : '搜索用户组'}
                  title={dirty ? '请先保存或取消当前修改' : undefined}
                  disabled={dirty || saving}
                />
              </div>
              {scope === 'owned' && (
                <button className={styles.createButton} onClick={() => void beginCreate()}>
                  <Plus size={15} aria-hidden /> 新建用户组
                </button>
              )}
              <div className={styles.groupList} data-testid="groups-dialog-list">
                {listError ? (
                  <button className={styles.retry} onClick={() => void loadGroups()}>
                    <AlertCircle size={15} /> 重新加载
                  </button>
                ) : groups.length === 0 && listLoading ? (
                  <LoadingState label="正在加载用户组…" />
                ) : groups.length === 0 ? (
                  <EmptyState label="暂无用户组" />
                ) : (
                  groups.map((group) => (
                    <button
                      key={group.id}
                      className={selectedId === group.id && !creating ? styles.groupActive : styles.groupButton}
                      onClick={() => void selectGroup(group.id)}
                    >
                      <span>{group.name}</span>
                      <small className={styles.groupMeta}>
                        {group.memberCount} 人
                      </small>
                    </button>
                  ))
                )}
              </div>
            </aside>

            <main
              ref={mainRef}
              className={styles.main}
              aria-busy={detailLoading}
              data-testid="groups-dialog-main"
            >
              {conflictMessage && (
                <div className={styles.conflict} role="alert">
                  <div><AlertCircle size={16} aria-hidden /><span>{conflictMessage}</span></div>
                  <ActionButton label="加载最新内容" variant="secondary" onClick={() => void loadLatest()} />
                </div>
              )}
              {creating ? (
                <GroupEditor
                  title="新建用户组"
                  name={draftName}
                  setName={setDraftName}
                  members={draftMembers}
                  setMembers={setDraftMembers}
                  saving={saving}
                  onSave={() => void save()}
                  onCancel={cancelEdit}
                />
              ) : detailLoading ? (
                <div className={styles.detailLoading}><LoadingState label="正在加载用户组…" /></div>
              ) : detailError ? (
                <button className={styles.retry} onClick={() => selectedId && void loadDetail(selectedId)}>
                  <AlertCircle size={15} /> 重新加载用户组
                </button>
              ) : detail ? (
                detail.isOwner ? (
                  <>
                    <GroupEditor
                      title={detail.name}
                      name={draftName}
                      setName={setDraftName}
                      members={draftMembers}
                      setMembers={setDraftMembers}
                      saving={saving}
                      frozen={detail.frozen}
                      onSave={() => void save()}
                      onCancel={cancelEdit}
                    />
                    <div className={styles.actionsBand}>
                      <div className={styles.transfer}>
                        <UserPicker
                          value={transferTo}
                          onChange={setTransferTo}
                          label="新用户组拥有者"
                          placeholder="搜索新拥有者"
                        />
                        <button className={styles.secondaryButton} disabled={!transferTo || dirty || saving} onClick={() => void transfer()}>
                          转移
                        </button>
                      </div>
                      <IconButton label={dirty ? '请先保存或取消修改' : '删除用户组'} danger disabled={dirty || saving} onClick={() => void remove()}>
                        <Trash2 size={16} />
                      </IconButton>
                    </div>
                  </>
                ) : (
                  <ReadonlyGroup group={detail} />
                )
              ) : (
                <EmptyState label="选择一个用户组" />
              )}
            </main>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function GroupEditor({
  title,
  name,
  setName,
  members,
  setMembers,
  saving,
  frozen = false,
  onSave,
  onCancel,
}: {
  title: string;
  name: string;
  setName: (value: string) => void;
  members: UserSearchResult[];
  setMembers: (users: UserSearchResult[]) => void;
  saving: boolean;
  frozen?: boolean;
  onSave: () => void;
  onCancel: () => void;
}) {
  return (
    <form className={styles.editor} onSubmit={(event) => {
      event.preventDefault();
      onSave();
    }}>
      <div className={styles.editorHeader}>
        <h3>{title}</h3>
        {frozen && <span className={styles.frozen}>已冻结</span>}
      </div>
      <label className={styles.label}>
        名称
        <input value={name} onChange={(event) => setName(event.target.value)} disabled={frozen} maxLength={120} />
      </label>
      <div className={styles.label}>成员</div>
      <UserMultiPicker users={members} onChange={setMembers} label="添加用户组成员" />
      <div className={styles.editorActions}>
        <ActionButton label="取消" variant="secondary" disabled={saving} onClick={onCancel} />
        <ActionButton
          label={saving ? '保存中…' : '保存'}
          type="submit"
          disabled={saving || frozen || !name.trim()}
        />
      </div>
    </form>
  );
}

function ReadonlyGroup({ group }: { group: CustomGroupDetail }) {
  return (
    <div className={styles.editor}>
      <div className={styles.editorHeader}>
        <h3>{group.name}</h3>
        {group.frozen && <span className={styles.frozen}>已冻结</span>}
      </div>
      <div className={styles.owner}>拥有者：{group.ownerDisplayName}</div>
      <div className={styles.memberRows}>
        {group.members.map((member) => (
          <div key={member.id}>
            <span>{member.displayName}</span>
            <small>{member.username}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

function sameMemberIds(left: string[], right: string[]): boolean {
  if (left.length !== right.length) return false;
  const sortedLeft = [...left].sort();
  const sortedRight = [...right].sort();
  return sortedLeft.every((value, index) => value === sortedRight[index]);
}

function groupSummary(group: CustomGroupDetail): CustomGroup {
  const { members: _members, revision: _revision, ...summary } = group;
  return summary;
}

function sortGroups(groups: CustomGroup[]): CustomGroup[] {
  return [...groups].sort((left, right) => left.name.localeCompare(right.name, 'zh-CN'));
}
