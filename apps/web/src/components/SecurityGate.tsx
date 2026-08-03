import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  Copy,
  KeyRound,
  LockKeyhole,
  LogOut,
  RefreshCw,
  RotateCcw,
  ShieldCheck,
  Upload,
  UserRoundCheck,
} from 'lucide-react';
import type { LegacyMigrationStatusResponse, SecurityPhase } from '@mima/client-core';
import type {
  AccountCryptoResetRequest,
  EnterpriseRecoveryCandidate,
  EnterpriseRecoveryRequest,
  EnterpriseRecoveryWorkspace,
  SessionUser,
  VaultCryptoState,
} from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import type { LocalAccessReason } from '../state/local-access.ts';
import { useUi } from '../state/ui-store.ts';
import { LoadingState } from './AsyncState.tsx';
import { EnterpriseRecoveryRequestPanel } from './EnterpriseRecoveryRequestPanel.tsx';
import { RecoveryKeyManager } from './RecoveryKeyManager.tsx';
import styles from './SecurityGate.module.css';

export function SecurityGate({
  phase,
  user,
  localAccessReason = null,
  onReauthenticate,
  onLoggedOut,
}: {
  phase: Exclude<SecurityPhase, 'unauthenticated' | 'unlocked-online' | 'unlocked-offline'>;
  user: SessionUser | null;
  localAccessReason?: LocalAccessReason;
  onReauthenticate?: () => void;
  onLoggedOut: () => void;
}) {
  if (phase === 'unlocking') {
    return <LoadingState variant="page" label="正在本机验证主密码并打开密码库…" />;
  }
  if (phase === 'rotating-identity') {
    return <LoadingState variant="page" label="正在更新账号安全并撤销旧设备…" />;
  }
  if (phase === 'setup-required') return <SetupPanel user={user} onLoggedOut={onLoggedOut} />;
  if (phase === 'account-reset') return <AccountResetPanel user={user} onLoggedOut={onLoggedOut} />;
  if (phase === 'migration-required') return <MigrationPanel user={user} onLoggedOut={onLoggedOut} />;
  if (phase === 'rekey-blocked') return <RekeyPanel onLoggedOut={onLoggedOut} />;
  return (
    <UnlockPanel
      user={user}
      localAccessReason={localAccessReason}
      onReauthenticate={onReauthenticate}
      onLoggedOut={onLoggedOut}
    />
  );
}

function SetupPanel({ user, onLoggedOut }: { user: SessionUser | null; onLoggedOut: () => void }) {
  const { zeroKnowledge } = useApp();
  const toast = useUi((state) => state.toast);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmationRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const password = passwordRef.current?.value ?? '';
    const confirmation = confirmationRef.current?.value ?? '';
    setBusy(true);
    try {
      await zeroKnowledge.setup(password, confirmation);
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '主密码设置失败');
    } finally {
      if (passwordRef.current) passwordRef.current.value = '';
      if (confirmationRef.current) confirmationRef.current.value = '';
      setBusy(false);
    }
  };

  return (
    <GateShell onLoggedOut={onLoggedOut}>
      <ShieldCheck size={24} className={styles.icon} aria-hidden />
      <h1>创建主密码</h1>
      <p>这是你在Mima中唯一需要记住的密码，用于在当前设备解开端到端加密的密码内容。</p>
      <ul className={styles.promiseList}>
        <li>无论从平台官网、飞书或任何中间平台进入，账号登录只确认你的身份和权限。</li>
        <li>主密码不会发送给平台服务端、任何中间平台或管理员。</li>
        <li>以后输入一次，工作台和浏览器扩展会一起解锁。</li>
      </ul>
      <form className={styles.form} autoComplete="on" onSubmit={submit}>
        {user && <BrowserCredentialAccount id="new-main-password-username" user={user} />}
        <label htmlFor="new-main-password">主密码（本机解密）</label>
        <input
          id="new-main-password"
          ref={passwordRef}
          name="password"
          type="password"
          autoComplete="new-password"
          autoFocus
          minLength={12}
          maxLength={256}
        />
        <span className={styles.help}>至少 12 个字符，建议使用自己容易记住、别人难以猜到的长句。</span>
        <label htmlFor="confirm-main-password">再次输入主密码（本机解密）</label>
        <input
          id="confirm-main-password"
          ref={confirmationRef}
          name="password-confirmation"
          type="password"
          autoComplete="new-password"
          minLength={12}
          maxLength={256}
        />
        <button className={styles.primary} type="submit" disabled={busy}>
          {busy ? '正在保护密码库…' : '创建主密码并继续'}
        </button>
      </form>
      <div className={styles.boundary}>
        主密码、密码库名称和库内内容都不会以明文发送到服务器，包括平台管理员也不能从平台直接查看。
      </div>
      {user?.isLocalPlatformAdmin && (
        <AdminToolsDisclosure label="管理员设置（不影响主密码创建）">
          <RecoveryKeyManager />
          <AdminAccountResetApprovals />
        </AdminToolsDisclosure>
      )}
    </GateShell>
  );
}

function UnlockPanel({
  user,
  localAccessReason,
  onReauthenticate,
  onLoggedOut,
}: {
  user: SessionUser | null;
  localAccessReason: LocalAccessReason;
  onReauthenticate?: () => void;
  onLoggedOut: () => void;
}) {
  const { zeroKnowledge } = useApp();
  const toast = useUi((state) => state.toast);
  const connection = useMeta((state) => state.connection);
  const passwordRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const [resetting, setResetting] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const password = passwordRef.current?.value ?? '';
    if (!password) return;
    setBusy(true);
    try {
      await zeroKnowledge.unlock(password);
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '解锁失败');
    } finally {
      if (passwordRef.current) passwordRef.current.value = '';
      setBusy(false);
    }
  };

  return (
    <GateShell onLoggedOut={onLoggedOut}>
      <LockKeyhole size={24} className={styles.icon} aria-hidden />
      <h1>解锁你的密码库</h1>
      <p>
        {localAccessReason
          ? '这台浏览器保存着你之前使用的加密数据。输入主密码只会在本机解开密码内容。'
          : '你已经完成账号登录。再输入主密码，是为了在这台设备解开加密的密码内容。'}
      </p>
      <ul className={styles.promiseList}>
        <li>账号登录确认你是谁，主密码负责解开密码库。</li>
        <li>主密码只在当前设备使用，不会发送给平台服务端或任何中间平台。</li>
        <li>输入一次后，工作台和浏览器扩展会一起解锁。</li>
      </ul>
      {connection === 'offline' && localAccessReason === 'session-expired' ? (
        <div className={styles.notice}>
          <strong>账号登录已过期，当前只使用这台设备保存的数据。</strong>
          <span>同步和权限管理要在重新登录后恢复。</span>
          {onReauthenticate && (
            <button type="button" className={styles.noticeAction} onClick={onReauthenticate}>
              <RefreshCw size={15} aria-hidden />重新登录
            </button>
          )}
        </div>
      ) : connection === 'offline' ? (
        <div className={styles.notice}>网络暂时不可用，将使用这台设备保存的数据。</div>
      ) : null}
      <form className={styles.form} autoComplete="on" onSubmit={submit}>
        {user && <BrowserCredentialAccount id="main-password-username" user={user} />}
        <label htmlFor="main-password">主密码（本机解密）</label>
        <input
          id="main-password"
          ref={passwordRef}
          name="password"
          type="password"
          autoComplete="current-password"
          autoFocus
          maxLength={256}
        />
        <button className={styles.primary} type="submit" disabled={busy}>{busy ? '正在解锁密码库…' : '解锁密码库'}</button>
      </form>
      <button className={styles.secondary} type="button" onClick={() => setResetting((value) => !value)}>
        {resetting ? '返回主密码解锁' : '忘记主密码或没有可用设备'}
      </button>
      {resetting && <StartAccountResetForm />}
      {user?.isLocalPlatformAdmin && <AdminAccountResetApprovals />}
    </GateShell>
  );
}

function BrowserCredentialAccount({ id, user }: { id: string; user: SessionUser }) {
  return (
    <>
      <label htmlFor={id}>账号</label>
      <input
        id={id}
        className={styles.accountInput}
        name="username"
        type="text"
        value={user.username}
        autoComplete="username"
        readOnly
      />
      <span className={styles.help}>{user.displayName} · 已完成账号登录</span>
    </>
  );
}

function StartAccountResetForm() {
  const { zeroKnowledge } = useApp();
  const toast = useUi((state) => state.toast);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmationRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      await zeroKnowledge.startAccountCryptoReset(
        passwordRef.current?.value ?? '',
        confirmationRef.current?.value ?? '',
      );
      toast('warn', '解锁重置申请已提交，需要两名不同的系统管理员审批');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '解锁重置申请提交失败');
    } finally {
      if (passwordRef.current) passwordRef.current.value = '';
      if (confirmationRef.current) confirmationRef.current.value = '';
      setBusy(false);
    }
  };
  return (
    <form className={styles.resetForm} onSubmit={submit}>
      <div className={styles.notice}>这不会找回原主密码。优先请仍能打开密码库的所有者重新授权；确需企业恢复时，每次要由两位管理员共同确认，并由三份离线恢复材料中的任意两份共同完成。</div>
      <label htmlFor="reset-main-password">新的主密码</label>
      <input id="reset-main-password" ref={passwordRef} type="password" autoComplete="new-password" minLength={12} maxLength={256} />
      <label htmlFor="reset-main-password-confirmation">再次输入新的主密码</label>
      <input id="reset-main-password-confirmation" ref={confirmationRef} type="password" autoComplete="new-password" minLength={12} maxLength={256} />
      <button className={styles.primary} type="submit" disabled={busy}>
        {busy ? '正在准备重置申请…' : '提交密码库解锁重置申请'}
      </button>
    </form>
  );
}

function AccountResetPanel({ user, onLoggedOut }: { user: SessionUser | null; onLoggedOut: () => void }) {
  const { zeroKnowledge } = useApp();
  const toast = useUi((state) => state.toast);
  const [request, setRequest] = useState<AccountCryptoResetRequest | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);
  const load = async () => {
    setLoading(true);
    try {
      const requests = await zeroKnowledge.accountCryptoResetRequests();
      setRequest(requests.find((entry) => entry.targetUserId === user?.id
        && (entry.status === 'pending' || entry.status === 'approved')) ?? null);
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '解锁重置状态加载失败');
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { void load(); }, [user?.id]);
  const cancel = async () => {
    if (!request) return;
    setBusy(true);
    try {
      await zeroKnowledge.cancelAccountCryptoReset(request);
      toast('info', '密码库解锁重置已取消');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '取消失败');
    } finally {
      setBusy(false);
    }
  };
  const activate = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!request) return;
    setBusy(true);
    try {
      await zeroKnowledge.activateAccountCryptoReset(request, passwordRef.current?.value ?? '');
      toast('warn', '新的解锁信息已启用。系统会在仍能打开密码库的拥有者下次解锁后自动恢复访问；确认无人能打开时再使用企业恢复。');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '密码库解锁重置未完成');
    } finally {
      if (passwordRef.current) passwordRef.current.value = '';
      setBusy(false);
    }
  };
  return (
    <GateShell onLoggedOut={onLoggedOut}>
      <UserRoundCheck size={24} className={styles.icon} aria-hidden />
      <h1>重置密码库解锁</h1>
      <p>原来的主密码和解锁能力无法找回。管理员审批只允许你在这台浏览器重新建立解锁能力，不能查看你的密码库内容。</p>
      {loading && <LoadingState label="正在加载审批状态…" />}
      {!loading && !request && <div className={styles.notice}>没有进行中的重置请求。请返回锁定页重新发起。</div>}
      {request && (
        <>
          <div className={styles.account}>已审批 {request.approvalUserIds.length}/2 人 · 有效期至 {new Date(request.expiresAt).toLocaleString()}</div>
          <div className={styles.boundary}>请求摘要：{request.requestDigest.slice(0, 16)}… 审批后不会自动完成；必须回到发起申请的这台浏览器，输入新主密码确认。</div>
          {request.status === 'approved' && (
            <form className={styles.form} onSubmit={activate}>
              <label htmlFor="activate-reset-main-password">新的主密码</label>
              <input id="activate-reset-main-password" ref={passwordRef} type="password" autoComplete="current-password" maxLength={256} />
              <button className={styles.primary} type="submit" disabled={busy}>{busy ? '正在验证新主密码…' : '验证新主密码并完成重置'}</button>
            </form>
          )}
          <div className={styles.actions}>
            <button type="button" onClick={() => void load()} disabled={busy}><RefreshCw size={15} aria-hidden />刷新状态</button>
            <button type="button" onClick={() => void cancel()} disabled={busy}>取消重置</button>
          </div>
        </>
      )}
      {user?.isLocalPlatformAdmin && <AdminAccountResetApprovals />}
    </GateShell>
  );
}

export function AdminAccountResetApprovals({
  showEmpty = false,
  recoveryWorkspace = null,
  onRecoveryChanged,
}: {
  showEmpty?: boolean;
  recoveryWorkspace?: EnterpriseRecoveryWorkspace | null;
  onRecoveryChanged?: () => void | Promise<void>;
} = {}) {
  const { api, zeroKnowledge } = useApp();
  const currentUserId = useMeta((state) => state.user?.id ?? '');
  const toast = useUi((state) => state.toast);
  const [requests, setRequests] = useState<AccountCryptoResetRequest[]>([]);
  const [recoveries, setRecoveries] = useState<EnterpriseRecoveryRequest[]>([]);
  const [candidates, setCandidates] = useState<EnterpriseRecoveryCandidate[]>([]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const load = async () => {
    setLoading(true);
    try {
      const values = await zeroKnowledge.accountCryptoResetRequests();
      const [recoveryValues, candidateValues] = recoveryWorkspace
        ? [recoveryWorkspace.requests, recoveryWorkspace.candidates]
        : await Promise.all([api.recoveryRequests(), api.recoveryCandidates()]);
      setRequests(values.filter((entry) =>
        entry.targetUserId !== currentUserId
        && ((entry.status === 'pending' || entry.status === 'approved')
          ? new Date(entry.expiresAt).getTime() > Date.now()
          : entry.status === 'activated' && entry.affectedVaultIds.length > 0),
      ));
      setRecoveries(recoveryValues);
      setCandidates(candidateValues);
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '待审批请求加载失败');
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { void load(); }, [currentUserId, recoveryWorkspace]);
  const approve = async (request: AccountCryptoResetRequest) => {
    const confirmed = await useUi.getState().requestConfirm({
      title: '批准账户加密身份重置？',
      body: `申请人：${request.targetUserId}\n请求摘要：${request.requestDigest}\n有效期：${new Date(request.expiresAt).toLocaleString('zh-CN', { hour12: false })}\n批准后将计入双人审批，并允许申请人启用新的加密身份。请先与申请人核对完整摘要。`,
      confirmText: '摘要一致，批准',
      cancelText: '返回核对',
      danger: true,
    });
    if (!confirmed) return;
    setBusyId(request.id);
    try {
      await zeroKnowledge.approveAccountCryptoReset(request);
      toast('info', '审批已绑定到该请求摘要');
      await load();
      await onRecoveryChanged?.();
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '审批失败');
    } finally {
      setBusyId(null);
    }
  };
  const createRecovery = async (request: AccountCryptoResetRequest, vaultId: string) => {
    setBusyId(`${request.id}:${vaultId}`);
    try {
      await api.createRecoveryRequest({
        idempotencyKey: crypto.randomUUID(),
        vaultId,
        targetUserId: request.targetUserId,
        targetDeviceId: request.candidateDevice.id,
        targetEncryptionPublicKey: request.encryptionPublicKey,
        targetKeyVersion: request.newKeyVersion,
        reason: 'account_reset',
        accountResetRequestId: request.id,
      });
      toast('info', '该密码库的企业恢复请求已发起，仍需两名不同管理员审批');
      await load();
      await onRecoveryChanged?.();
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '企业恢复请求发起失败');
    } finally {
      setBusyId(null);
    }
  };
  const approveRecovery = async (request: EnterpriseRecoveryRequest) => {
    setBusyId(request.id);
    try {
      await api.approveRecoveryRequest(request.id, {
        idempotencyKey: crypto.randomUUID(),
        requestDigest: request.requestDigest,
      });
      toast('info', '企业恢复审批已绑定到请求摘要');
      await load();
      await onRecoveryChanged?.();
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '企业恢复审批失败');
    } finally {
      setBusyId(null);
    }
  };
  const createPersonalRecovery = async (candidate: EnterpriseRecoveryCandidate) => {
    setBusyId(`candidate:${candidate.vaultId}`);
    try {
      await api.createRecoveryRequest({
        idempotencyKey: crypto.randomUUID(),
        vaultId: candidate.vaultId,
        targetUserId: candidate.targetUserId,
        targetDeviceId: candidate.targetDeviceId,
        targetEncryptionPublicKey: candidate.targetEncryptionPublicKey,
        targetKeyVersion: candidate.targetKeyVersion,
        reason: 'lost_all_devices',
      });
      toast('info', '企业恢复请求已发起，仍需两名不同管理员审批和离线恢复材料');
      await load();
      await onRecoveryChanged?.();
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '企业恢复请求发起失败');
    } finally {
      setBusyId(null);
    }
  };
  if (loading) return <LoadingState label="正在核对待审批请求…" />;
  if (requests.length === 0 && candidates.length === 0) {
    return showEmpty ? (
      <section className={styles.adminSection} aria-label="恢复协助与密码库解锁重置审批">
        <div className={styles.notice}>当前没有需要你审批或发起协助的恢复请求。</div>
      </section>
    ) : null;
  }
  return (
    <section className={styles.adminSection} aria-label="恢复协助与密码库解锁重置审批">
      <h2>待处理的恢复协助</h2>
      <p>管理员只能发起和审批流程，不能直接查看密码库内容。完整恢复仍需两名不同管理员审批，并由两名材料保管人在隔离设备联合处理。</p>
      {candidates.map((candidate) => {
        const recovery = recoveries.find((entry) =>
          entry.vaultId === candidate.vaultId &&
          entry.targetUserId === candidate.targetUserId &&
          (entry.status === 'pending' || entry.status === 'approved'));
        const approvedByMe = recovery?.approvalUserIds.includes(currentUserId) ?? false;
        return (
          <div className={styles.approvalRow} key={`candidate:${candidate.vaultId}`}>
            <div>
              <strong>{candidate.targetDisplayName} · 个人密码库需要企业恢复</strong>
              <span>
                {candidate.targetUsername} · 密码库 {candidate.vaultId.slice(0, 8)} · {recovery
                  ? `${recovery.approvalUserIds.length}/2 人已审批`
                  : '当前设备暂时打不开这个密码库'}
              </span>
            </div>
            {!recovery ? (
              <button
                type="button"
                disabled={busyId !== null}
                onClick={() => void createPersonalRecovery(candidate)}
              >
                {busyId === `candidate:${candidate.vaultId}` ? '发起中…' : '核对后发起恢复'}
              </button>
            ) : (
              <button
                type="button"
                disabled={approvedByMe || recovery.status === 'approved' || recovery.status === 'completed' || busyId !== null}
                onClick={() => void approveRecovery(recovery)}
              >
                {approvedByMe ? '已审批' : recovery.status === 'approved' ? '已完成双人审批' : '审批恢复'}
              </button>
            )}
          </div>
        );
      })}
      {requests.length > 0 && <h2>待审批的解锁重置</h2>}
      {requests.length > 0 && <p>解锁重置只为用户建立新的本机解锁能力，管理员仍看不到密码库内容。请通过公司流程核对申请人和请求摘要。</p>}
      {requests.map((request) => {
        if (request.status === 'activated') {
          return (
            <div className={styles.recoveryGroup} key={request.id}>
              <strong>{request.targetUserId} · 无人可解锁时的企业恢复</strong>
              {request.affectedVaultIds.map((vaultId) => {
                const recovery = recoveries.find((entry) =>
                  entry.accountResetRequestId === request.id && entry.vaultId === vaultId,
                );
                const approvedByMe = recovery?.approvalUserIds.includes(currentUserId) ?? false;
                return (
                  <div className={styles.approvalRow} key={vaultId}>
                    <div>
                      <strong>密码库 {vaultId.slice(0, 8)}</strong>
                      <span>{recovery
                        ? `${recovery.approvalUserIds.length}/2 人已审批 · ${recovery.targetCapability === 'metadata' ? '仅审计信息' : '全部内容'}`
                        : '仅在没有拥有者能够解锁时发起'}</span>
                    </div>
                    {!recovery ? (
                      <button type="button" disabled={busyId !== null} onClick={() => void createRecovery(request, vaultId)}>
                        {busyId === `${request.id}:${vaultId}` ? '发起中…' : '确认无人可解锁后发起'}
                      </button>
                    ) : (
                      <button
                        type="button"
                        disabled={approvedByMe || recovery.status === 'completed' || busyId !== null}
                        onClick={() => void approveRecovery(recovery)}
                      >
                        {approvedByMe ? '已审批' : recovery.status === 'approved' ? '补充审批' : '审批恢复'}
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          );
        }
        const approved = request.approvalUserIds.includes(currentUserId);
        return (
          <div className={styles.approvalRow} key={request.id}>
            <div>
              <strong>{request.targetUserId}</strong>
              <span>{request.requestDigest.slice(0, 12)}… · {request.approvalUserIds.length}/2 人</span>
            </div>
            <button type="button" disabled={approved || busyId !== null} onClick={() => void approve(request)}>
              {approved ? '已审批' : busyId === request.id ? '提交中…' : '核对后批准'}
            </button>
          </div>
        );
      })}
    </section>
  );
}

function MigrationPanel({
  user,
  onLoggedOut,
}: {
  user: SessionUser | null;
  onLoggedOut: () => void;
}) {
  const { zeroKnowledge } = useApp();
  const vaultCrypto = useMeta((state) => state.vaultCrypto);
  const vaults = useMeta((state) => state.vaults);
  const pendingStates = Object.values(vaultCrypto).filter((state) => state.status !== 'e2ee');
  const toast = useUi((state) => state.toast);
  const [refreshKey, setRefreshKey] = useState(0);
  const automaticPersonalRetryStarted = useRef(false);
  const automaticPersonalRetryKey = pendingStates
    .filter((state) => vaults[state.vaultId]?.kind === 'personal')
    .map((state) => state.vaultId)
    .sort()
    .join(',');
  const refreshAll = async () => {
    await zeroKnowledge.refresh();
    setRefreshKey((value) => value + 1);
  };
  useEffect(() => {
    if (!automaticPersonalRetryKey || automaticPersonalRetryStarted.current) return;
    automaticPersonalRetryStarted.current = true;
    const timer = window.setTimeout(() => {
      void zeroKnowledge.refresh()
        .then(() => setRefreshKey((value) => value + 1))
        .catch((error) => {
          toast('error', error instanceof Error ? error.message : '个人密码库自动准备失败');
        });
    }, 600);
    return () => window.clearTimeout(timer);
  }, [automaticPersonalRetryKey, toast, zeroKnowledge]);
  return (
    <GateShell onLoggedOut={onLoggedOut}>
      <KeyRound size={24} className={styles.icon} aria-hidden />
      <h1>正在准备工作台</h1>
      <p>系统会自动准备“我的密码库”。只有检测到需要迁移的历史内容时，才会显示额外步骤。</p>
      <div className={styles.boundary}>
        密码库名称和内容都会在当前浏览器加密后再上传，服务器只保存加密后的数据。
      </div>
      <div className={styles.migrationList}>
        {pendingStates.map((state) => (
          <MigrationVaultRow
            key={state.vaultId}
            cryptoState={state}
            refreshKey={refreshKey}
            personal={vaults[state.vaultId]?.kind === 'personal'}
            canDiscard={vaults[state.vaultId]?.kind === 'team'}
          />
        ))}
      </div>
      {user?.isLocalPlatformAdmin && (
        <AdminToolsDisclosure label="管理员：企业恢复设置">
          <RecoveryKeyManager />
        </AdminToolsDisclosure>
      )}
      <button
        className={styles.secondary}
        onClick={() => void refreshAll().catch((error) => {
          toast('error', error instanceof Error ? error.message : '迁移状态刷新失败');
        })}
      >
        <RefreshCw size={16} aria-hidden />
        重新检查
      </button>
    </GateShell>
  );
}

function MigrationVaultRow({
  cryptoState,
  refreshKey,
  personal,
  canDiscard,
}: {
  cryptoState: VaultCryptoState;
  refreshKey: number;
  personal: boolean;
  canDiscard: boolean;
}) {
  const { zeroKnowledge } = useApp();
  const toast = useUi((state) => state.toast);
  const [status, setStatus] = useState<LegacyMigrationStatusResponse | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const job = status?.job ?? null;

  const load = async () => {
    setError(null);
    try {
      setStatus(await zeroKnowledge.legacyMigrationStatus(cryptoState.vaultId));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '无法读取迁移状态');
    }
  };

  useEffect(() => {
    void load();
  }, [cryptoState.vaultId, refreshKey]);

  const run = async (label: string, action: () => Promise<LegacyMigrationStatusResponse | void>) => {
    setBusy(label);
    setError(null);
    try {
      const next = await action();
      if (next) setStatus(next);
      else await load();
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : '迁移操作失败';
      setError(message);
      toast('error', message);
      await load();
    } finally {
      setBusy(null);
    }
  };

  const copyJobId = async () => {
    if (!job) return;
    try {
      await navigator.clipboard.writeText(job.id);
      toast('info', '迁移任务 ID 已复制');
    } catch {
      toast('error', '无法复制迁移任务 ID');
    }
  };

  const currentStatus = status?.status ?? (cryptoState.status === 'preparing' ? 'pending' : null);
  const isEmptyInitialization = currentStatus === 'pending'
    && status?.emptyVaultInitializationAllowed === true;
  const prepared = job ? zeroKnowledge.hasPreparedLegacyMigration(cryptoState.vaultId, job.id) : false;
  return (
    <section className={styles.migrationRow} aria-busy={busy !== null}>
      {!isEmptyInitialization && (
        <div className={styles.migrationHeader}>
          <div>
            <strong>密码库 {cryptoState.vaultId.slice(0, 8)}</strong>
            <span>{currentStatus ? migrationStatusText(currentStatus) : '正在读取状态'}</span>
          </div>
          <button type="button" className={styles.iconButton} onClick={() => void load()} disabled={busy !== null} title="刷新状态">
            <RefreshCw size={15} aria-hidden />
          </button>
        </div>
      )}

      {job && !isEmptyInitialization && (
        <div className={styles.jobLine}>
          <code>{job.id}</code>
          <button type="button" className={styles.iconButton} onClick={() => void copyJobId()} title="复制迁移任务 ID">
            <Copy size={15} aria-hidden />
          </button>
        </div>
      )}

      {job && !isEmptyInitialization && (
        <div className={styles.progressLine}>
          条目 {job.verifiedItemCount}/{job.expectedItemCount} · 历史内容 {job.verifiedSecretVersionCount}/{job.expectedSecretVersionCount}
        </div>
      )}

      {currentStatus === 'frozen' && (
        <p className={styles.rowHelp}>旧数据已停止写入。运维使用上面的任务 ID 运行隔离迁移程序后，在这里刷新。</p>
      )}
      {currentStatus === 'encrypting' && !prepared && (
        <p className={styles.rowHelp}>领取后请保持本页打开。本页关闭会销毁临时密钥，必须回滚并重新开始。</p>
      )}
      {status && !status.materials && currentStatus !== 'complete' && (
        <div className={styles.inlineNotice}>{isEmptyInitialization
          ? '当前设备的本地密钥材料尚未准备完成。请重新检查；若问题持续存在，请确认已在这台设备完成主密码设置。'
          : '有成员尚未设置主密码，暂时不能生成完整密钥分发。'}</div>
      )}
      {isEmptyInitialization && status?.materials?.recoveryKey === null && (
        <div className={styles.inlineNotice}>
          企业恢复可稍后配置，不影响现在创建和使用密码库。
        </div>
      )}
      {error && <div className={styles.inlineError}>{error}</div>}

      {!isEmptyInitialization && <div className={styles.migrationActions}>
        {currentStatus === 'pending' && (
          <button
            type="button"
            onClick={() => void run('start', () => zeroKnowledge.startLegacyMigration(cryptoState.vaultId))}
            disabled={busy !== null || !status?.materials}
          >
            <Upload size={15} aria-hidden />
            {busy === 'start' ? '正在冻结…' : '冻结并开始迁移'}
          </button>
        )}
        {currentStatus === 'encrypting' && !prepared && (
          <button
            type="button"
            onClick={() => void run('convert', () => zeroKnowledge.convertLegacyMigration(cryptoState.vaultId))}
            disabled={busy !== null || !status?.materials}
          >
            <KeyRound size={15} aria-hidden />
            {busy === 'convert' ? '正在本地转换…' : '领取并本地转换'}
          </button>
        )}
        {currentStatus === 'encrypting' && prepared && (
          <button
            type="button"
            onClick={() => void run('verify', () => zeroKnowledge.verifyLegacyMigration(cryptoState.vaultId))}
            disabled={busy !== null}
          >
            <CheckCircle2 size={15} aria-hidden />
            {busy === 'verify' ? '正在核对…' : '核对记录与接收人'}
          </button>
        )}
        {currentStatus === 'verifying' && (
          <button
            type="button"
            onClick={() => void run('cutover', () => zeroKnowledge.cutoverLegacyMigration(cryptoState.vaultId))}
            disabled={busy !== null || !prepared}
          >
            <CheckCircle2 size={15} aria-hidden />
            {busy === 'cutover' ? '正在切换…' : '切换到零知识密文'}
          </button>
        )}
        {job && ['frozen', 'encrypting', 'verifying'].includes(currentStatus ?? '') && (
          <button
            type="button"
            className={styles.secondaryAction}
            onClick={() => void run('rollback', () => zeroKnowledge.rollbackLegacyMigration(cryptoState.vaultId))}
            disabled={busy !== null}
          >
            <RotateCcw size={15} aria-hidden />
            {busy === 'rollback' ? '正在回滚…' : '回滚本次迁移'}
          </button>
        )}
      </div>}

      {isEmptyInitialization && (
        <div className={styles.emptyVaultOption}>
          {personal ? (
            <>
              <strong>正在自动准备“我的密码库”</strong>
              <span>完成后会直接进入工作台，无需再设置密码库名称。</span>
            </>
          ) : (
            <>
              <strong>创建密码库</strong>
              <span>输入一个自己容易识别的名称。名称也会在当前浏览器加密后再上传。</span>
              <PendingVaultInitializer
                vaultId={cryptoState.vaultId}
                canInitialize={Boolean(status?.materials)}
                canDiscard={canDiscard}
              />
            </>
          )}
        </div>
      )}
    </section>
  );
}

function PendingVaultInitializer({
  vaultId,
  canInitialize,
  canDiscard,
}: {
  vaultId: string;
  canInitialize: boolean;
  canDiscard: boolean;
}) {
  const { zeroKnowledge } = useApp();
  const toast = useUi((state) => state.toast);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    try {
      await zeroKnowledge.initializePendingVault(vaultId, name);
      useUi.getState().selectVault(vaultId);
      toast('info', '密码库已创建');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '密码库初始化失败');
    } finally {
      setBusy(false);
    }
  };
  const discard = async () => {
    const confirmed = await useUi.getState().requestConfirm({
      title: '清理未完成的空密码库',
      body: '只会删除这个未完成、没有任何条目和加密材料的团队密码库。已经初始化或包含内容时，服务器会拒绝操作。',
      confirmText: '清理空库',
      cancelText: '保留',
      danger: true,
    });
    if (!confirmed) return;
    setBusy(true);
    try {
      await zeroKnowledge.deleteUninitializedVault(vaultId);
      toast('info', '未完成的空密码库已清理');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '空密码库清理失败');
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className={styles.pendingVault} onSubmit={submit}>
      <label htmlFor={`pending-vault-${vaultId}`}>密码库名称</label>
      <div>
        <input
          id={`pending-vault-${vaultId}`}
          value={name}
          onChange={(event) => setName(event.target.value)}
          maxLength={120}
          placeholder="例如：我的密码"
          required
        />
        <button type="submit" disabled={!canInitialize || busy || !name.trim()}>
          {!canInitialize ? '等待本地密钥准备完成' : busy ? '正在创建…' : '创建并进入工作台'}
        </button>
      </div>
      {canDiscard && (
        <button
          className={styles.discardPendingVault}
          type="button"
          disabled={busy}
          onClick={() => void discard()}
        >
          放弃并清理这个空库
        </button>
      )}
    </form>
  );
}

function AdminToolsDisclosure({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <details className={styles.adminTools}>
      <summary><ChevronRight className={styles.disclosureChevron} size={15} aria-hidden />{label}</summary>
      <div>{children}</div>
    </details>
  );
}

function migrationStatusText(status: LegacyMigrationStatusResponse['status']): string {
  const labels: Record<LegacyMigrationStatusResponse['status'], string> = {
    pending: '尚未开始',
    preparing: '正在准备冻结点',
    frozen: '等待隔离迁移程序',
    encrypting: '等待浏览器加密',
    verifying: '核对完成，等待切换',
    cutover: '正在切换',
    complete: '迁移已完成',
    failed: '迁移失败',
  };
  return labels[status];
}

function RekeyPanel({ onLoggedOut }: { onLoggedOut: () => void }) {
  const { zeroKnowledge } = useApp();
  const toast = useUi((state) => state.toast);
  const vaultCrypto = useMeta((state) => state.vaultCrypto);
  const vaults = useMeta((state) => state.vaults);
  const [busyVaultId, setBusyVaultId] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const recoveryPending = Object.values(vaultCrypto).filter((state) => state.recoveryRequired === true);
  const pending = Object.values(vaultCrypto).filter((state) =>
    state.status === 'rekey_required' && state.recoveryRequired !== true);
  const complete = async (vaultId: string) => {
    setBusyVaultId(vaultId);
    try {
      await zeroKnowledge.completeVaultRekey(vaultId);
      toast('info', '密码库访问已安全更新');
    } catch (error) {
      toast('error', friendlyRekeyError(error));
    } finally {
      setBusyVaultId(null);
    }
  };
  return (
    <GateShell onLoggedOut={onLoggedOut}>
      <AlertTriangle size={24} className={styles.warningIcon} aria-hidden />
      <h1>{recoveryPending.length > 0 ? '部分密码库需要企业恢复' : '密码库正在安全更新'}</h1>
      <p>{recoveryPending.length > 0
        ? '当前设备暂时打不开这些个人密码库。在恢复完成前，系统不会返回对应条目；账号登录成功也不能代替密码库解锁。'
        : '移除成员、降低权限或撤销设备后，系统会更新密码库的访问保护。完成前暂时不能修改，避免旧权限继续获得新内容。'}</p>
      {pending.length > 0 && (
        <div className={styles.boundary}>对方已经看过或离线保存的旧内容无法远程抹除；这次安全更新只会阻止其继续获得后续内容。</div>
      )}
      {recoveryPending.map((state) => (
        <div className={styles.pendingVault} key={`recovery:${state.vaultId}`}>
          <strong>密码库 {state.vaultId.slice(0, 8)} · 需要企业恢复</strong>
          <span>请联系系统管理员在“企业恢复”中发起协助。请求仍需两名不同管理员审批，并由两名材料保管人使用两份离线材料联合处理；个人库只会恢复到你本人绑定的设备。</span>
        </div>
      ))}
      {recoveryPending.length > 0 && (
        <EnterpriseRecoveryRequestPanel recoveryRequired />
      )}
      {pending.map((state) => (
        <div className={styles.pendingVault} key={state.vaultId}>
          <span>{vaults[state.vaultId]?.name ?? '密码库'} · 等待安全更新</span>
          <button
            type="button"
            disabled={busyVaultId !== null || !zeroKnowledge.rekeyTaskId(state.vaultId)}
            onClick={() => void complete(state.vaultId)}
          >
            {busyVaultId === state.vaultId ? '正在本机更新…' : '完成安全更新'}
          </button>
        </div>
      ))}
      <button
        className={styles.primary}
        disabled={refreshing || busyVaultId !== null}
        onClick={() => void (async () => {
          setRefreshing(true);
          try {
            await zeroKnowledge.refresh();
            toast('info', '状态已刷新；仍显示的密码库需要继续完成安全更新');
          } catch (error) {
            toast('error', friendlyRekeyError(error));
          } finally {
            setRefreshing(false);
          }
        })()}
      >
        <RefreshCw size={16} aria-hidden />
        {refreshing ? '正在刷新…' : '刷新状态'}
      </button>
    </GateShell>
  );
}

function friendlyRekeyError(error: unknown): string {
  const message = error instanceof Error ? error.message : '';
  if (message.includes('条目类型不受支持') || message.includes('密钥轮换缺少条目类型材料')) {
    return '密码库仍在安全更新，本次没有写入新数据。请刷新页面后重试；若仍失败，请联系管理员并提供密码库名称。';
  }
  return message || '安全更新未完成，请刷新页面后重试；若仍失败，请联系管理员。';
}

function GateShell({ children, onLoggedOut }: { children: React.ReactNode; onLoggedOut: () => void }) {
  const { zeroKnowledge } = useApp();
  const logout = async () => {
    try {
      await zeroKnowledge.logout();
    } finally {
      onLoggedOut();
    }
  };
  return (
    <main className={styles.wrap}>
      <section className={styles.panel} aria-live="polite">
        <div className={styles.brand}><KeyRound size={18} aria-hidden /> Mima</div>
        {children}
        <button className={styles.logout} type="button" onClick={() => void logout()}>
          <LogOut size={15} aria-hidden />
          退出登录
        </button>
      </section>
    </main>
  );
}
