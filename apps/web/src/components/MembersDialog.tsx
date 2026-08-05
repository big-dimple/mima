import { useEffect, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { KeyRound, RefreshCw, ShieldAlert, X, Trash2 } from 'lucide-react';
import type {
  CustomGroup,
  Membership,
  MembershipRole,
  SubjectKind,
  UserSearchResult,
  VaultOwnershipTransfer,
} from '@mima/contracts';
import { canManageMembers, resolveEffectiveRole } from '@mima/domain';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { IconButton } from './IconButton.tsx';
import { UserPicker } from './UserPicker.tsx';
import dialogStyles from './dialog.module.css';
import styles from './MembersDialog.module.css';

const ROLES: { value: MembershipRole; label: string; desc: string }[] = [
  { value: 'viewer', label: '查看', desc: '可查看条目信息、密码和敏感内容' },
  { value: 'editor', label: '编辑', desc: '可读写条目' },
  { value: 'owner', label: '拥有者', desc: '可管理成员' },
  { value: 'auditor', label: '审计', desc: '只能查看操作记录' },
];

const EMPTY_MEMBERSHIPS: Membership[] = [];

type OwnershipTransferState = {
  vaultId: string | null;
  status: 'loading' | 'loaded' | 'error';
  transfer: VaultOwnershipTransfer | null;
};

type BatchGrantStatus = {
  vaultId: string;
  state: 'pending' | 'success' | 'failed';
  message: string;
};

export function MembersDialog() {
  const { api, zeroKnowledge } = useApp();
  const vaultId = useUi((s) => s.membersDialogVaultId);
  const vault = useMeta((s) => (vaultId ? s.vaults[vaultId] : undefined));
  const user = useMeta((s) => s.user);
  const memberships = useMeta((s) =>
    vaultId ? (s.memberships[vaultId] ?? EMPTY_MEMBERSHIPS) : EMPTY_MEMBERSHIPS,
  );
  const vaults = useMeta((s) => s.vaults);
  const toast = useUi((s) => s.toast);

  const [knownUsers, setKnownUsers] = useState<UserSearchResult[]>([]);
  const [ownedGroups, setOwnedGroups] = useState<CustomGroup[]>([]);
  const [subjectKind, setSubjectKind] = useState<'user' | 'custom_group'>('user');
  const [subjectId, setSubjectId] = useState('');
  const [role, setRole] = useState<MembershipRole>('viewer');
  const [transferTo, setTransferTo] = useState('');
  const ownershipTransferRequestId = useRef(0);
  const batchRunId = useRef(0);
  const [ownershipTransferState, setOwnershipTransferState] = useState<OwnershipTransferState>({
    vaultId: null,
    status: 'loading',
    transfer: null,
  });
  const [removingMembershipKey, setRemovingMembershipKey] = useState<string | null>(null);
  const [acceptingTransfer, setAcceptingTransfer] = useState(false);
  const [cancellingTransfer, setCancellingTransfer] = useState(false);
  const [batchUserId, setBatchUserId] = useState('');
  const [batchRole, setBatchRole] = useState<'auditor' | 'viewer' | 'editor'>('viewer');
  const [batchStatuses, setBatchStatuses] = useState<BatchGrantStatus[]>([]);
  const [batchRunning, setBatchRunning] = useState(false);

  const ownershipTransfer = ownershipTransferState.vaultId === vaultId
    ? ownershipTransferState.transfer
    : null;
  const ownershipTransferStatus = ownershipTransferState.vaultId === vaultId
    ? ownershipTransferState.status
    : 'loading';
  const projects = Object.values(vaults)
    .filter((candidate) =>
      candidate.kind === 'team' &&
      candidate.projectContext?.kind === 'project' &&
      candidate.projectContext.visibleParentVaultId === vaultId
    )
    .sort((left, right) => left.name.localeCompare(right.name, 'zh-CN'));

  useEffect(() => {
    batchRunId.current += 1;
    setBatchUserId('');
    setBatchRole('viewer');
    setBatchStatuses([]);
    setBatchRunning(false);
    setRemovingMembershipKey(null);
  }, [vaultId]);

  const close = () => {
    ownershipTransferRequestId.current += 1;
    setOwnershipTransferState({ vaultId: null, status: 'loading', transfer: null });
    useUi.getState().openMembers(null);
  };

  const loadOwnershipTransfer = async () => {
    const targetVaultId = vaultId;
    if (!targetVaultId) return;
    const requestId = ++ownershipTransferRequestId.current;
    setOwnershipTransferState({ vaultId: targetVaultId, status: 'loading', transfer: null });
    try {
      const transfer = await zeroKnowledge.getVaultOwnershipTransfer(targetVaultId);
      if (ownershipTransferRequestId.current !== requestId) return;
      setOwnershipTransferState({ vaultId: targetVaultId, status: 'loaded', transfer });
    } catch {
      if (ownershipTransferRequestId.current !== requestId) return;
      setOwnershipTransferState({ vaultId: targetVaultId, status: 'error', transfer: null });
    }
  };

  useEffect(() => {
    if (!vaultId) return;
    let current = true;
    const userIds = memberships
      .filter((membership) => membership.subjectKind === 'user')
      .map((membership) => membership.subjectId);
    const batches = chunk(userIds, 50);
    void Promise.all(batches.map((ids) => api.searchUsers('', ids, 50)))
      .then((results) => {
        if (!current) return;
        setKnownUsers(uniqueUsers(results.flatMap((result) => result.users)));
      })
      .catch(() => undefined);
    void api.groups('owned').then((groups) => {
      if (current) setOwnedGroups(groups);
    }).catch(() => undefined);
    void loadOwnershipTransfer();
    return () => {
      current = false;
      ownershipTransferRequestId.current += 1;
    };
  }, [api, memberships, vaultId, zeroKnowledge]);

  if (!vaultId || !vault) return null;

  const add = async () => {
    if (!subjectId) return;
    try {
      const result = await zeroKnowledge.setVaultMembership(vaultId, subjectKind, subjectId, role);
      setSubjectId('');
      toast('info', result.rekeyRequired
        ? '成员权限已更新，正在安全更新密码库访问'
        : result.envelopeTasks?.withoutProfile
          ? '成员已加入；对方设置主密码后，系统会自动准备团队访问'
          : '成员授权已保存，系统正在自动准备团队访问');
    } catch (err) {
      toast('error', err instanceof Error ? err.message : '操作失败');
    }
  };

  const runBatchGrant = async (retryFailedOnly = false) => {
    if (!batchUserId || projects.length === 0 || batchRunning) return;
    const failedIds = new Set(batchStatuses
      .filter((status) => status.state === 'failed')
      .map((status) => status.vaultId));
    const targets = retryFailedOnly
      ? projects.filter((project) => failedIds.has(project.id))
      : projects;
    if (targets.length === 0) return;
    const runId = ++batchRunId.current;
    setBatchRunning(true);
    setBatchStatuses((current) => {
      const untouched = retryFailedOnly
        ? current.filter((status) => !failedIds.has(status.vaultId))
        : [];
      return [
        ...untouched,
        ...targets.map((project) => ({
          vaultId: project.id,
          state: 'pending' as const,
          message: '等待处理',
        })),
      ];
    });
    for (const project of targets) {
      if (runId !== batchRunId.current) return;
      try {
        const result = await zeroKnowledge.setVaultMembership(
          project.id,
          'user',
          batchUserId,
          batchRole,
          'grant_or_upgrade',
          false,
        );
        if (runId !== batchRunId.current) return;
        setBatchStatuses((current) => current.map((status) => status.vaultId === project.id
          ? {
              ...status,
              state: 'success',
              message: result.envelopeTasks?.withoutProfile
                ? '授权完成，对方设置主密码后将自动准备'
                : '授权完成，访问将自动准备',
            }
          : status));
      } catch (error) {
        if (runId !== batchRunId.current) return;
        setBatchStatuses((current) => current.map((status) => status.vaultId === project.id
          ? {
              ...status,
              state: 'failed',
              message: error instanceof Error ? error.message : '授权失败',
            }
          : status));
      }
    }
    if (runId !== batchRunId.current) return;
    try {
      await zeroKnowledge.refresh();
    } catch {
      toast('warn', '授权结果已经保留，但成员列表刷新失败；请稍后刷新工作台');
    } finally {
      if (runId === batchRunId.current) setBatchRunning(false);
    }
  };

  const remove = async (kind: SubjectKind, id: string) => {
    const membership = memberships.find((candidate) => candidate.subjectKind === kind && candidate.subjectId === id);
    if (!membership || removingMembershipKey) return;
    const subjectName = nameOf(kind, id);
    const roleLabel = ROLES.find((candidate) => candidate.value === membership.role)?.label ?? membership.role;
    const removingSelf = kind === 'user' && id === user?.id;
    const confirmed = await useUi.getState().requestConfirm({
      title: removingSelf ? '移除自己的密码库授权？' : '移除密码库授权？',
      body: `将移除 ${subjectName} 的“${roleLabel}”授权。系统会保留其通过其他用户组或直接授权获得的有效访问；如果实际访问能力降低，将自动启动安全更新。${removingSelf ? ' 这是你自己的授权，完成后你可能立即失去当前密码库的访问。' : ''}`,
      confirmText: '确认移除',
      cancelText: '保留授权',
      danger: true,
    });
    if (!confirmed) return;
    const operationKey = `${kind}:${id}`;
    setRemovingMembershipKey(operationKey);
    try {
      const result = await zeroKnowledge.removeVaultMembership(vaultId, kind, id);
      toast('info', result.rekeyRequired
        ? '授权已移除，正在安全更新密码库访问'
        : result.retainedAccess
          ? kind === 'user'
            ? '这条授权已移除；对方仍可通过其他授权访问，无需额外处理'
            : '用户组授权已移除；部分同事仍可通过其他授权访问，无需额外处理'
          : '授权已移除，无需额外处理');
    } catch (err) {
      toast('error', err instanceof Error ? err.message : '操作失败');
    } finally {
      setRemovingMembershipKey(null);
    }
  };

  const nameOf = (kind: SubjectKind, id: string) =>
    kind === 'user'
      ? (knownUsers.find((candidate) => candidate.id === id)?.displayName ?? id)
      : kind === 'custom_group'
        ? (ownedGroups.find((group) => group.id === id)?.name ?? id)
        : `旧目录组 · ${id}`;

  const myRole = user
    ? resolveEffectiveRole(memberships, { userId: user.id, groups: user.groups })
    : null;
  const isOwner = canManageMembers(myRole);
  const directOwnerCount = memberships.filter((membership) =>
    membership.subjectKind === 'user' && membership.role === 'owner'
  ).length;

  const transfer = async () => {
    if (!transferTo) return;
    const name = nameOf('user', transferTo);
    const confirmed = await useUi.getState().requestConfirm({
      title: '转移所有权',
      body: `确定把「${vault?.name}」的所有权转移给 ${name}？你将降为编辑角色。`,
      confirmText: '转移',
      cancelText: '取消',
      danger: true,
    });
    if (!confirmed) return;
    try {
      const result = await zeroKnowledge.transferVaultOwnership(vaultId!, transferTo);
      if (result.vaultId !== vaultId) throw new Error('所有权转移结果与当前密码库不一致，请刷新后重试');
      setOwnershipTransferState({ vaultId, status: 'loaded', transfer: result });
      setTransferTo('');
      toast('info', `已发起转移，等待 ${name} 在已解锁设备上确认接收`);
    } catch (err) {
      toast('error', err instanceof Error ? err.message : '转移失败');
    }
  };

  const acceptTransfer = async () => {
    if (
      !ownershipTransfer ||
      ownershipTransferState.vaultId !== vaultId ||
      ownershipTransfer.vaultId !== vaultId ||
      ownershipTransfer.toOwnerUserId !== user?.id
    ) return;
    const confirmed = await useUi.getState().requestConfirm({
      title: '确认接收所有权',
      body: `确认接收「${vault.name}」的所有权？完成后你将负责成员管理和访问安全。`,
      confirmText: '确认接收',
      cancelText: '暂不接收',
    });
    if (!confirmed) return;
    setAcceptingTransfer(true);
    try {
      const result = await zeroKnowledge.acceptVaultOwnershipTransfer(ownershipTransfer);
      if (result.vaultId !== vaultId) throw new Error('所有权转移结果与当前密码库不一致，请刷新后重试');
      setOwnershipTransferState({ vaultId, status: 'loaded', transfer: result });
      toast('info', result.status === 'completed'
        ? '已接收所有权，正在安全更新密码库访问'
        : '已确认接收，系统正在完成所有权交接');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '确认接收失败');
      await loadOwnershipTransfer();
    } finally {
      setAcceptingTransfer(false);
    }
  };

  const cancelTransfer = async (decision: 'cancel' | 'decline') => {
    if (
      !ownershipTransfer ||
      ownershipTransferState.vaultId !== vaultId ||
      ownershipTransfer.vaultId !== vaultId
    ) return;
    const confirmed = await useUi.getState().requestConfirm({
      title: decision === 'cancel' ? '取消所有权转移' : '拒绝接收所有权',
      body: decision === 'cancel'
        ? '取消后，对方现有的成员权限不会改变，你可以重新发起转移。'
        : '拒绝后，你现有的成员权限不会改变。',
      confirmText: decision === 'cancel' ? '取消转移' : '拒绝接收',
      cancelText: '返回',
      danger: true,
    });
    if (!confirmed) return;
    setCancellingTransfer(true);
    try {
      await zeroKnowledge.cancelVaultOwnershipTransfer(ownershipTransfer, decision);
      setOwnershipTransferState({ vaultId, status: 'loaded', transfer: null });
      toast('info', decision === 'cancel' ? '已取消所有权转移' : '已拒绝接收所有权');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '处理所有权转移失败');
      await loadOwnershipTransfer();
    } finally {
      setCancellingTransfer(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(open) => !open && !batchRunning && close()}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={[dialogStyles.content, styles.content].join(' ')}>
          <Dialog.Title className={dialogStyles.title}>成员管理 · {vault.name}</Dialog.Title>
          <Dialog.Description className={dialogStyles.description}>
            管理密码库成员、权限与所有权。
          </Dialog.Description>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭" disabled={batchRunning}><X size={16} /></button>
          </Dialog.Close>

          {isOwner && directOwnerCount <= 1 && (
            <div className={styles.ownerRisk} role="status">
              <ShieldAlert size={18} aria-hidden />
              <div>
                <strong>当前只有一位拥有者</strong>
                <span>如果唯一拥有者无法继续管理密码库或离职未交接，自动密钥交付会暂停。建议现在增加第二位拥有者。</span>
              </div>
              <button type="button" onClick={() => {
                setSubjectKind('user');
                setRole('owner');
                requestAnimationFrame(() => {
                  document.querySelector<HTMLElement>('[aria-label="授权用户"]')?.focus();
                });
              }}>增加第二位拥有者</button>
            </div>
          )}

          <div className={styles.tableWrapper}>
            <table className={styles.table}>
              <thead>
                <tr><th>主体</th><th>类型</th><th>角色</th><th /></tr>
              </thead>
              <tbody>
                {memberships.length === 0 && (
                  <tr><td colSpan={4} className={styles.empty}>暂无授权</td></tr>
                )}
                {memberships.map((m) => (
                  <tr key={m.id}>
                    <td data-label="主体">{nameOf(m.subjectKind, m.subjectId)}</td>
                    <td className={styles.kind} data-label="类型">
                      {m.subjectKind === 'user' ? '用户' : m.subjectKind === 'custom_group' ? '平台用户组' : '旧目录组'}
                    </td>
                    <td data-label="角色">{ROLES.find((r) => r.value === m.role)?.label ?? m.role}</td>
                    <td data-label="操作">
                      {isOwner && !(
                        m.subjectKind === 'user' &&
                        m.role === 'owner' &&
                        directOwnerCount <= 1
                      ) && (
                        <IconButton
                          label="移除授权"
                          danger
                          disabled={removingMembershipKey !== null}
                          onClick={() => void remove(m.subjectKind, m.subjectId)}
                        >
                          <Trash2 size={14} />
                        </IconButton>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {isOwner && (
            <div className={styles.addArea}>
              <div className={styles.subjectTabs} aria-label="授权对象类型">
                <button className={subjectKind === 'user' ? styles.subjectActive : ''} onClick={() => {
                  setSubjectKind('user');
                  setSubjectId('');
                }}>用户</button>
                <button className={subjectKind === 'custom_group' ? styles.subjectActive : ''} onClick={() => {
                  setSubjectKind('custom_group');
                  setSubjectId('');
                  if (role === 'owner') setRole('viewer');
                }}>平台用户组</button>
              </div>
              <div className={styles.grantRow}>
                {subjectKind === 'user' ? (
                  <UserPicker
                    value={subjectId}
                    onChange={(id, selectedUser) => {
                      setSubjectId(id);
                      if (selectedUser) {
                        setKnownUsers((current) => current.some((item) => item.id === selectedUser.id)
                          ? current
                          : [...current, selectedUser]);
                      }
                    }}
                    label="授权用户"
                  />
                ) : (
                  <select className={styles.select} value={subjectId} onChange={(event) => setSubjectId(event.target.value)} aria-label="平台用户组">
                    <option value="">选择用户组…</option>
                    {ownedGroups.filter((group) => !group.frozen).map((group) => (
                      <option key={group.id} value={group.id}>{group.name}</option>
                    ))}
                  </select>
                )}
                <select className={styles.select} value={role} onChange={(event) => setRole(event.target.value as MembershipRole)} aria-label="权限">
                  {ROLES.filter((candidate) => subjectKind === 'user' || candidate.value !== 'owner').map((candidate) => (
                    <option key={candidate.value} value={candidate.value}>{candidate.label}</option>
                  ))}
                </select>
                <button className={styles.addBtn} onClick={() => void add()} disabled={!subjectId}>授权</button>
              </div>
            </div>
          )}
          {isOwner && projects.length > 0 && (
            <div className={styles.batchBox}>
              <div className={styles.transferTitle}>批量授权下属项目</div>
              <p className={styles.note}>
                将同一用户逐个授权到 {projects.length} 个项目。已成功的项目会保留，失败项可单独重试；不会批量降权、撤权或授予拥有者。
              </p>
              <div className={styles.grantRow}>
                <UserPicker
                  value={batchUserId}
                  onChange={(id, selectedUser) => {
                    setBatchUserId(id);
                    setBatchStatuses([]);
                    if (selectedUser) {
                      setKnownUsers((current) => current.some((item) => item.id === selectedUser.id)
                        ? current
                        : [...current, selectedUser]);
                    }
                  }}
                  label="批量授权用户"
                />
                <select
                  className={styles.select}
                  value={batchRole}
                  onChange={(event) => {
                    setBatchRole(event.target.value as typeof batchRole);
                    setBatchStatuses([]);
                  }}
                  aria-label="批量权限"
                >
                  <option value="viewer">查看</option>
                  <option value="editor">编辑</option>
                  <option value="auditor">审计</option>
                </select>
                <button
                  className={styles.addBtn}
                  onClick={() => void runBatchGrant(false)}
                  disabled={!batchUserId || batchRunning}
                >
                  {batchRunning ? '授权中' : '开始授权'}
                </button>
              </div>
              {batchStatuses.length > 0 && (
                <div className={styles.batchResults} aria-live="polite">
                  <div className={styles.batchProgress}>
                    <span>
                      已完成 {batchStatuses.filter((status) => status.state !== 'pending').length} / {batchStatuses.length}
                    </span>
                    {batchStatuses.some((status) => status.state === 'failed') && !batchRunning && (
                      <button type="button" onClick={() => void runBatchGrant(true)}>
                        <RefreshCw size={13} aria-hidden />
                        仅重试失败项
                      </button>
                    )}
                  </div>
                  {batchStatuses.map((status) => {
                    const project = projects.find((candidate) => candidate.id === status.vaultId);
                    return (
                      <div className={styles.batchResult} data-state={status.state} key={status.vaultId}>
                        <strong>{project?.name ?? status.vaultId}</strong>
                        <span>{status.message}</span>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
          <p className={styles.note}>
            直接用户权限优先于用户组权限。审计权限只能查看操作记录，不能查看密码或敏感内容。
            团队密码库必须始终保留至少一名直接用户拥有者。
          </p>

          {ownershipTransferStatus === 'loading' && (
            <div className={styles.transferBox} role="status">
              <div className={styles.transferTitle}>正在检查所有权转移状态…</div>
            </div>
          )}

          {ownershipTransferStatus === 'error' && (
            <div className={styles.transferBox} role="alert">
              <div className={styles.transferTitle}>暂时无法确认所有权转移状态</div>
              <p className={styles.transferStatus}>为避免对错误的密码库执行操作，状态恢复前不会开放新的转移。</p>
              <button className={styles.cancelBtn} onClick={() => void loadOwnershipTransfer()}>
                <RefreshCw size={14} aria-hidden />重新加载
              </button>
            </div>
          )}

          {ownershipTransferStatus === 'loaded' && ownershipTransfer && (
            <div className={styles.transferBox} data-testid="ownership-transfer-status">
              <div className={styles.transferTitle}>待完成的所有权转移</div>
              <p className={styles.transferStatus}>
                {ownershipTransfer.acceptanceStatus === 'waiting'
                  ? !ownershipTransfer.envelopeReady
                    ? '系统正在自动准备目标用户的当前密码库访问；准备完成后才能确认接收。'
                    : ownershipTransfer.toOwnerUserId === user?.id
                      ? '当前设备已经可以打开密码库。确认前不会转移所有权。'
                      : `等待 ${nameOf('user', ownershipTransfer.toOwnerUserId)} 在已解锁设备上确认接收。`
                  : ownershipTransfer.status === 'completed'
                    ? '目标用户已确认，所有权转移已完成。'
                    : '目标用户已确认，系统正在完成所有权交接。'}
              </p>
              {ownershipTransfer.acceptanceStatus === 'waiting' &&
                ownershipTransfer.toOwnerUserId === user?.id && (
                  <div className={styles.transferActions}>
                    <button
                      className={styles.acceptBtn}
                      disabled={acceptingTransfer || cancellingTransfer || !ownershipTransfer.envelopeReady}
                      onClick={() => void acceptTransfer()}
                    >
                      <KeyRound size={14} aria-hidden />
                      {acceptingTransfer
                        ? '正在确认'
                        : ownershipTransfer.envelopeReady ? '确认接收' : '正在准备'}
                    </button>
                    <button
                      className={styles.cancelBtn}
                      disabled={acceptingTransfer || cancellingTransfer}
                      onClick={() => void cancelTransfer('decline')}
                    >
                      <X size={14} aria-hidden />
                      {cancellingTransfer ? '正在处理' : '拒绝'}
                    </button>
                  </div>
                )}
              {ownershipTransfer.acceptanceStatus === 'waiting' &&
                ownershipTransfer.fromOwnerUserId === user?.id && (
                  <button
                    className={styles.cancelBtn}
                    disabled={cancellingTransfer}
                    onClick={() => void cancelTransfer('cancel')}
                  >
                    <X size={14} aria-hidden />
                    {cancellingTransfer ? '正在取消' : '取消转移'}
                  </button>
                )}
            </div>
          )}

          {isOwner && ownershipTransferStatus === 'loaded' && !ownershipTransfer && (
            <div className={styles.transferBox}>
              <div className={styles.transferTitle}>转移所有权</div>
              <div className={styles.transferRow}>
                <select
                  className={styles.select}
                  value={transferTo}
                  onChange={(event) => setTransferTo(event.target.value)}
                  aria-label="新拥有者"
                >
                  <option value="">选择已有成员…</option>
                  {memberships.filter((membership) =>
                    membership.subjectKind === 'user' &&
                    membership.subjectId !== user?.id &&
                    (membership.role === 'viewer' || membership.role === 'editor')
                  ).map((membership) => (
                    <option key={membership.id} value={membership.subjectId}>
                      {nameOf('user', membership.subjectId)} · {membership.role === 'editor' ? '编辑' : '查看'}
                    </option>
                  ))}
                </select>
                <button className={styles.addBtn} onClick={() => void transfer()} disabled={!transferTo}>
                  转移
                </button>
              </div>
              <p className={styles.note}>请先在上方把对方加入为查看或编辑成员。系统会自动准备其密码库访问；对方在自己的已解锁设备上确认后，你才会降为编辑。</p>
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function chunk<T>(values: T[], size: number): T[][] {
  const batches: T[][] = [];
  for (let index = 0; index < values.length; index += size) {
    batches.push(values.slice(index, index + size));
  }
  return batches;
}

function uniqueUsers(values: UserSearchResult[]): UserSearchResult[] {
  return [...new Map(values.map((user) => [user.id, user])).values()];
}
