import { useEffect, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { KeyRound, RefreshCw, ShieldAlert, X, Trash2 } from 'lucide-react';
import type {
  CustomGroup,
  Membership,
  MembershipRole,
  SubjectKind,
  UserSearchResult,
  VaultEnvelopeTask,
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

type EnvelopeTasksState = {
  vaultId: string | null;
  status: 'loading' | 'loaded' | 'error';
  tasks: VaultEnvelopeTask[];
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
  const envelopeTasksRequestId = useRef(0);
  const batchRunId = useRef(0);
  const [envelopeTasksState, setEnvelopeTasksState] = useState<EnvelopeTasksState>({
    vaultId: null,
    status: 'loading',
    tasks: [],
  });
  const [completingTaskId, setCompletingTaskId] = useState<string | null>(null);
  const [ownershipTransfer, setOwnershipTransfer] = useState<VaultOwnershipTransfer | null>(null);
  const [acceptingTransfer, setAcceptingTransfer] = useState(false);
  const [cancellingTransfer, setCancellingTransfer] = useState(false);
  const [batchUserId, setBatchUserId] = useState('');
  const [batchRole, setBatchRole] = useState<'auditor' | 'viewer' | 'editor'>('viewer');
  const [batchStatuses, setBatchStatuses] = useState<BatchGrantStatus[]>([]);
  const [batchRunning, setBatchRunning] = useState(false);

  const envelopeTasks = envelopeTasksState.vaultId === vaultId ? envelopeTasksState.tasks : [];
  const envelopeTasksStatus = envelopeTasksState.vaultId === vaultId
    ? envelopeTasksState.status
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
  }, [vaultId]);

  const close = () => {
    envelopeTasksRequestId.current += 1;
    setEnvelopeTasksState({ vaultId: null, status: 'loading', tasks: [] });
    useUi.getState().openMembers(null);
  };

  const loadEnvelopeTasks = async () => {
    const targetVaultId = vaultId;
    if (!targetVaultId) return;
    const requestId = ++envelopeTasksRequestId.current;
    setEnvelopeTasksState({ vaultId: targetVaultId, status: 'loading', tasks: [] });
    try {
      const tasks = await zeroKnowledge.listEnvelopeTasks(targetVaultId);
      if (envelopeTasksRequestId.current !== requestId) return;
      setEnvelopeTasksState({ vaultId: targetVaultId, status: 'loaded', tasks });
    } catch {
      if (envelopeTasksRequestId.current !== requestId) return;
      setEnvelopeTasksState({ vaultId: targetVaultId, status: 'error', tasks: [] });
    }
  };

  const loadOwnershipTransfer = async () => {
    if (!vaultId) return;
    try {
      setOwnershipTransfer(await zeroKnowledge.getVaultOwnershipTransfer(vaultId));
    } catch {
      setOwnershipTransfer(null);
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
    void loadEnvelopeTasks();
    void loadOwnershipTransfer();
    return () => {
      current = false;
      envelopeTasksRequestId.current += 1;
    };
  }, [api, memberships, vaultId, zeroKnowledge]);

  if (!vaultId || !vault) return null;

  const add = async () => {
    if (!subjectId) return;
    envelopeTasksRequestId.current += 1;
    setEnvelopeTasksState({ vaultId, status: 'loading', tasks: [] });
    try {
      const result = await zeroKnowledge.setVaultMembership(vaultId, subjectKind, subjectId, role);
      await loadEnvelopeTasks();
      setSubjectId('');
      toast('info', result.rekeyRequired
        ? '成员权限已更新，正在安全更新密码库访问'
        : result.envelopeTasks?.withoutProfile
          ? '成员已加入；对方设置主密码后，请回来完成访问开通'
          : result.envelopeTasks?.pending
            ? '成员已加入；还需在“待开通访问”中完成开通'
            : '成员授权和访问开通已完成');
    } catch (err) {
      await loadEnvelopeTasks();
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
                ? '已授权，等待对方设置主密码'
                : result.envelopeTasks?.pending
                  ? '已授权，待完成访问开通'
                  : '授权完成',
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
    close();
    try {
      const result = await zeroKnowledge.removeVaultMembership(vaultId, kind, id);
      toast('info', result.rekeyRequired
        ? '授权已移除，正在安全更新密码库访问'
        : result.retainedAccess
          ? kind === 'user'
            ? '这条授权已移除；对方仍可通过其他授权访问，无需额外处理'
            : '用户组授权已移除；部分同事仍可通过其他授权访问，无需额外处理'
          : '授权已移除；对方此前尚未开通访问，无需额外处理');
    } catch (err) {
      toast('error', err instanceof Error ? err.message : '操作失败');
    }
  };

  const nameOf = (kind: SubjectKind, id: string) =>
    kind === 'user'
      ? (knownUsers.find((candidate) => candidate.id === id)?.displayName ?? id)
      : kind === 'custom_group'
        ? (ownedGroups.find((group) => group.id === id)?.name ?? id)
        : `旧目录组 · ${id}`;

  const membershipTasks = (membership: Membership) => envelopeTasks.filter((task) =>
    task.authorizationRef === membership.subjectId &&
    task.authorizationKind === authorizationKind(membership.subjectKind)
  );

  const myRole = user
    ? resolveEffectiveRole(memberships, { userId: user.id, groups: user.groups })
    : null;
  const isOwner = canManageMembers(myRole);
  const directOwnerCount = memberships.filter((membership) =>
    membership.subjectKind === 'user' && membership.role === 'owner'
  ).length;
  const readyOwnerCount = envelopeTasksStatus === 'loaded'
    ? memberships.filter((membership) =>
        membership.subjectKind === 'user' &&
        membership.role === 'owner' &&
        membershipTasks(membership).length === 0
      ).length
    : 0;

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
      setOwnershipTransfer(result);
      setTransferTo('');
      await loadEnvelopeTasks();
      toast('info', `已发起转移，等待 ${name} 在已解锁设备上确认接收`);
    } catch (err) {
      toast('error', err instanceof Error ? err.message : '转移失败');
    }
  };

  const acceptTransfer = async () => {
    if (!ownershipTransfer || ownershipTransfer.toOwnerUserId !== user?.id) return;
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
      setOwnershipTransfer(result);
      await loadEnvelopeTasks();
      toast('info', result.status === 'completed'
        ? '已接收所有权，正在安全更新密码库访问'
        : '已确认接收，等待当前拥有者完成访问开通');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '确认接收失败');
      await loadOwnershipTransfer();
    } finally {
      setAcceptingTransfer(false);
    }
  };

  const cancelTransfer = async (decision: 'cancel' | 'decline') => {
    if (!ownershipTransfer) return;
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
      setOwnershipTransfer(null);
      toast('info', decision === 'cancel' ? '已取消所有权转移' : '已拒绝接收所有权');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '处理所有权转移失败');
      await loadOwnershipTransfer();
    } finally {
      setCancellingTransfer(false);
    }
  };

  const completeTask = async (task: VaultEnvelopeTask) => {
    setCompletingTaskId(task.id);
    try {
      await zeroKnowledge.completeEnvelopeTask(task);
      await loadEnvelopeTasks();
      toast('info', '密码库访问已开通');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '访问开通失败');
    } finally {
      setCompletingTaskId(null);
    }
  };

  const membershipKeyStatus = (membership: Membership) => {
    if (envelopeTasksStatus === 'loading') return '正在检查访问状态';
    if (envelopeTasksStatus === 'error') return '暂时无法确认';
    const tasks = membershipTasks(membership);
    if (tasks.some((task) => !task.recipientProfile)) return '等待对方设置主密码';
    if (tasks.length > 0) return `${tasks.length} 项待开通`;
    return '已开通';
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

          {isOwner && envelopeTasksStatus === 'loaded' && readyOwnerCount < 2 && (
            <div className={styles.ownerRisk} role="status">
              <ShieldAlert size={18} aria-hidden />
              <div>
                <strong>{directOwnerCount <= 1 ? '当前只有一位拥有者' : '第二位拥有者尚未就绪'}</strong>
                <span>{directOwnerCount <= 1
                  ? '如果唯一拥有者忘记主密码、设备不可用或离职未交接，日常授权会中断。建议现在增加第二位拥有者。'
                  : '拥有者角色已经保存，但对方暂时还打不开当前密码库。完成访问开通前，唯一可用拥有者不能被移除或降权。'}</span>
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
                <tr><th>主体</th><th>类型</th><th>角色</th><th>访问状态</th><th /></tr>
              </thead>
              <tbody>
                {memberships.length === 0 && (
                  <tr><td colSpan={5} className={styles.empty}>暂无授权</td></tr>
                )}
                {memberships.map((m) => (
                  <tr key={m.id}>
                    <td data-label="主体">{nameOf(m.subjectKind, m.subjectId)}</td>
                    <td className={styles.kind} data-label="类型">
                      {m.subjectKind === 'user' ? '用户' : m.subjectKind === 'custom_group' ? '平台用户组' : '旧目录组'}
                    </td>
                    <td data-label="角色">{ROLES.find((r) => r.value === m.role)?.label ?? m.role}</td>
                    <td className={styles.kind} data-label="访问状态">{membershipKeyStatus(m)}</td>
                    <td data-label="操作">
                      {isOwner && !(
                        m.subjectKind === 'user' &&
                        m.role === 'owner' &&
                        (envelopeTasksStatus !== 'loaded' || (membershipTasks(m).length === 0 && readyOwnerCount <= 1))
                      ) && (
                        <IconButton label="移除授权" danger onClick={() => void remove(m.subjectKind, m.subjectId)}>
                          <Trash2 size={14} />
                        </IconButton>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {isOwner && envelopeTasksStatus === 'loaded' && envelopeTasks.length > 0 && (
            <div className={styles.addArea}>
              <div className={styles.transferTitle}>待开通访问</div>
              <p className={styles.taskHint}>这些同事已经获得权限，但还打不开当前密码库。由你在此开通即可，不需要对方领取文件。</p>
              {envelopeTasks.map((task) => (
                <div className={styles.taskRow} key={task.id}>
                  <span>
                    {nameOf('user', task.recipientUserId)} · {task.capability === 'metadata' ? '审计信息' : '完整访问'}
                  </span>
                  {task.recipientProfile ? (
                    <button
                      className={styles.addBtn}
                      disabled={completingTaskId !== null}
                      onClick={() => void completeTask(task)}
                    >
                      <KeyRound size={14} aria-hidden />
                      {completingTaskId === task.id ? '正在开通' : '开通'}
                    </button>
                  ) : (
                    <span className={styles.taskStatus}>等待对方设置主密码</span>
                  )}
                </div>
              ))}
            </div>
          )}

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

          {ownershipTransfer && (
            <div className={styles.transferBox} data-testid="ownership-transfer-status">
              <div className={styles.transferTitle}>待完成的所有权转移</div>
              <p className={styles.transferStatus}>
                {ownershipTransfer.acceptanceStatus === 'waiting'
                  ? !ownershipTransfer.envelopeReady
                    ? '当前拥有者需要先为对方开通当前密码库；开通前，对方不能确认接收。'
                    : ownershipTransfer.toOwnerUserId === user?.id
                      ? '当前设备已经可以打开密码库。确认前不会转移所有权。'
                      : `等待 ${nameOf('user', ownershipTransfer.toOwnerUserId)} 在已解锁设备上确认接收。`
                  : ownershipTransfer.status === 'completed'
                    ? '目标用户已确认，所有权转移已完成。'
                    : '目标用户已确认，等待当前拥有者完成访问开通。'}
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
                        : ownershipTransfer.envelopeReady ? '确认接收' : '等待开通'}
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

          {isOwner && !ownershipTransfer && (
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
              <p className={styles.note}>请先在上方把对方加入为查看或编辑成员，并完成访问开通。对方在自己的已解锁设备上确认后，你才会降为编辑。</p>
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function authorizationKind(kind: SubjectKind): VaultEnvelopeTask['authorizationKind'] {
  if (kind === 'custom_group') return 'custom_group';
  if (kind === 'group') return 'directory_group';
  return 'direct';
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
