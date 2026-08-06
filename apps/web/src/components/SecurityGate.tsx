import { useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
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
  EnterpriseRecoveryCase,
  EnterpriseRecoveryWorkspace,
  SessionUser,
  VaultCryptoState,
} from '@mima/contracts';
import { EnterpriseRecoveryCaseTransferSchema } from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import type { LocalAccessReason } from '../state/local-access.ts';
import { useUi } from '../state/ui-store.ts';
import { LoadingState } from './AsyncState.tsx';
import { EnterpriseRecoveryRequestPanel } from './EnterpriseRecoveryRequestPanel.tsx';
import { UserPicker } from './UserPicker.tsx';
import { readTextFile } from '../utils/read-text-file.ts';
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
  if (phase === 'migration-required') return <MigrationPanel onLoggedOut={onLoggedOut} />;
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
        主密码、密码库名称和库内内容都不会以明文发送到服务器，包括平台管理员也绝对无法查看受保护库。
      </div>
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
        {resetting ? '返回主密码解锁' : '忘记主密码'}
      </button>
      {resetting && <ForgotPasswordHelp />}
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

function ForgotPasswordHelp() {
  const { api, zeroKnowledge } = useApp();
  const currentUserId = useMeta((state) => state.user?.id ?? '');
  const toast = useUi((state) => state.toast);
  const passwordRef = useRef<HTMLInputElement>(null);
  const confirmationRef = useRef<HTMLInputElement>(null);
  const [recoveryCase, setRecoveryCase] = useState<EnterpriseRecoveryCase | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const load = async () => {
    setLoading(true);
    try {
      const cases = await api.recoveryCases();
      setRecoveryCase(cases.find((entry) => (
        entry.targetUserId === currentUserId
        && ['waiting_for_target', 'pending_approval', 'approved', 'processing'].includes(entry.status)
      )) ?? null);
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '恢复协助状态加载失败');
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { void load(); }, [currentUserId]);
  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!recoveryCase || recoveryCase.status !== 'waiting_for_target') return;
    setBusy(true);
    try {
      await zeroKnowledge.startForgotPasswordRecoveryCase(
        recoveryCase.id,
        passwordRef.current?.value ?? '',
        confirmationRef.current?.value ?? '',
      );
      toast('info', '新主密码已设置，正在等待两位管理员确认');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '新主密码设置失败');
    } finally {
      if (passwordRef.current) passwordRef.current.value = '';
      if (confirmationRef.current) confirmationRef.current.value = '';
      setBusy(false);
    }
  };
  if (loading) return <LoadingState label="正在查看管理员是否已发起协助…" />;
  if (!recoveryCase) {
    return (
      <div className={styles.resetForm}>
        <div className={styles.notice}>
          请在公司群里联系管理员，并直接说“我忘记主密码，请在企业恢复中心发起协助”。管理员发起后，刷新这里设置新主密码即可。
        </div>
        <button type="button" className={styles.secondary} onClick={() => void load()}>
          <RefreshCw size={15} aria-hidden />管理员已发起，刷新状态
        </button>
      </div>
    );
  }
  if (recoveryCase.status !== 'waiting_for_target') {
    return (
      <div className={styles.resetForm}>
        <div className={styles.notice}>{recoveryCase.status === 'pending_approval'
          ? `新主密码已准备好，正在等待管理员确认（${recoveryCase.approvalUserIds.length}/2）。无需停留本页，确认完成后请用新主密码重新登录。`
          : '管理员已经确认，系统正在自动恢复你的原有访问。'}</div>
        <button type="button" className={styles.secondary} onClick={() => void load()}>
          <RefreshCw size={15} aria-hidden />刷新状态
        </button>
      </div>
    );
  }
  return (
    <form className={styles.resetForm} onSubmit={submit}>
      <div className={styles.notice}>管理员已发起协助。请设置新主密码；原主密码不会被找回，管理员也不能登录你的账号或查看受保护库。</div>
      <label htmlFor="reset-main-password">新的主密码</label>
      <input id="reset-main-password" ref={passwordRef} type="password" autoComplete="new-password" minLength={12} maxLength={256} />
      <label htmlFor="reset-main-password-confirmation">再次输入新的主密码</label>
      <input id="reset-main-password-confirmation" ref={confirmationRef} type="password" autoComplete="new-password" minLength={12} maxLength={256} />
      <button className={styles.primary} type="submit" disabled={busy}>
        {busy ? '正在安全保存…' : '设置新主密码并等待确认'}
      </button>
    </form>
  );
}

function AccountResetPanel({ user, onLoggedOut }: { user: SessionUser | null; onLoggedOut: () => void }) {
  const { api, zeroKnowledge } = useApp();
  const toast = useUi((state) => state.toast);
  const [request, setRequest] = useState<AccountCryptoResetRequest | null>(null);
  const [recoveryCase, setRecoveryCase] = useState<EnterpriseRecoveryCase | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const activationStarted = useRef<string | null>(null);
  const load = async () => {
    try {
      const [requests, cases] = await Promise.all([
        zeroKnowledge.accountCryptoResetRequests(),
        api.recoveryCases(),
      ]);
      const activeRequest = requests.find((entry) => entry.targetUserId === user?.id
        && (entry.status === 'pending' || entry.status === 'approved')) ?? null;
      setRequest(activeRequest);
      setRecoveryCase(cases.find((entry) => entry.id === activeRequest?.caseId) ?? null);
      if (activeRequest?.status === 'approved'
        && activeRequest.caseId === null
        && activationStarted.current !== activeRequest.id
      ) {
        activationStarted.current = activeRequest.id;
        setBusy(true);
        try {
          await zeroKnowledge.activatePreparedAccountCryptoReset(activeRequest);
          toast('info', '新主密码已启用，系统正在自动恢复你原有的密码库访问');
        } catch (error) {
          activationStarted.current = null;
          toast('error', error instanceof Error ? error.message : '自动启用新主密码失败，请刷新重试');
        } finally {
          setBusy(false);
        }
      }
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '解锁重置状态加载失败');
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 3000);
    return () => window.clearInterval(timer);
  }, [user?.id]);
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
  return (
    <GateShell onLoggedOut={onLoggedOut}>
      <UserRoundCheck size={24} className={styles.icon} aria-hidden />
      <h1>正在恢复访问</h1>
      <p>你已经设置好新主密码。两位管理员确认后，新主密码会启用；需要恢复的原有访问由管理员继续处理。之后可在任意浏览器重新登录。</p>
      {loading && <LoadingState label="正在查看管理员确认进度…" />}
      {!loading && !request && <div className={styles.notice}>这次协助已经结束，请返回登录页重新进入。</div>}
      {request && (
        <>
          <div className={styles.account}>管理员已确认 {request.approvalUserIds.length}/2 人</div>
          <div className={styles.boundary}>{busy || request.status === 'approved'
            ? '确认已经完成，正在自动启用新主密码。'
            : `等待另一位管理员确认。有效期至 ${new Date(request.expiresAt).toLocaleString()}`}</div>
          {recoveryCase && <div className={styles.notice}>本次协助会恢复你原本已经拥有的权限，不会新增任何密码库权限。</div>}
          <div className={styles.actions}>
            <button type="button" onClick={() => void load()} disabled={busy}><RefreshCw size={15} aria-hidden />立即刷新</button>
            <button type="button" onClick={() => void cancel()} disabled={busy}>取消重置</button>
          </div>
        </>
      )}
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
  const { api } = useApp();
  const currentUserId = useMeta((state) => state.user?.id ?? '');
  const toast = useUi((state) => state.toast);
  const [cases, setCases] = useState<EnterpriseRecoveryCase[]>(recoveryWorkspace?.cases ?? []);
  const [targetUserId, setTargetUserId] = useState('');
  const [kind, setKind] = useState<EnterpriseRecoveryCase['kind']>('forgot_password');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const load = async () => {
    setLoading(true);
    try {
      setCases(await api.recoveryCases());
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '恢复协助加载失败');
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => setTargetUserId(''), [currentUserId]);
  useEffect(() => {
    if (recoveryWorkspace) {
      setCases(recoveryWorkspace.cases);
      setLoading(false);
      return;
    }
    void load();
  }, [currentUserId, recoveryWorkspace]);
  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!targetUserId) return;
    setBusyId('create');
    try {
      await api.createRecoveryCase({
        idempotencyKey: crypto.randomUUID(),
        kind,
        targetUserId,
      });
      setTargetUserId('');
      toast('info', '恢复协助已发起，等待用户设置新主密码');
      if (onRecoveryChanged) await onRecoveryChanged();
      else await load();
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '恢复协助发起失败');
    } finally {
      setBusyId(null);
    }
  };
  const approve = async (recoveryCase: EnterpriseRecoveryCase) => {
    const confirmed = await useUi.getState().requestConfirm({
      title: '确认帮助这位同事恢复？',
      body: `用户：${recoveryCase.targetDisplayName}（${recoveryCase.targetUsername}）\n场景：${recoveryCase.kind === 'forgot_password' ? '忘记主密码' : '交接中断后恢复原有权限'}\n涉及 ${recoveryCase.items.length} 个原本已有权限的密码库。请先通过公司沟通渠道确认本人身份。`,
      confirmText: '身份已确认，同意协助',
      cancelText: '暂不确认',
      danger: true,
    });
    if (!confirmed) return;
    setBusyId(recoveryCase.id);
    try {
      if (!recoveryCase.caseDigest) throw new Error('用户还没有设置新主密码');
      await api.approveRecoveryCase(recoveryCase.id, {
        idempotencyKey: crypto.randomUUID(),
        caseDigest: recoveryCase.caseDigest,
      });
      toast('info', '你的确认已记录；两人确认后，页面会提示下一步');
      if (onRecoveryChanged) await onRecoveryChanged();
      else await load();
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '审批失败');
    } finally {
      setBusyId(null);
    }
  };
  const downloadPackage = async (recoveryCase: EnterpriseRecoveryCase) => {
    setBusyId(`download:${recoveryCase.id}`);
    try {
      const value = await api.recoveryCasePackage(recoveryCase.id);
      downloadJson(`企业恢复案件-${recoveryCase.targetUsername}-${recoveryCase.id.slice(0, 8)}.json`, value);
      toast('info', '案件文件已下载，请带到断网电脑并在恢复向导中选择“处理恢复案件”');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '恢复包下载失败');
    } finally {
      setBusyId(null);
    }
  };
  const uploadTransfer = async (recoveryCase: EnterpriseRecoveryCase, file: File) => {
    setBusyId(`upload:${recoveryCase.id}`);
    try {
      const transfer = EnterpriseRecoveryCaseTransferSchema.parse(JSON.parse(await readTextFile(file)));
      if (!recoveryCase.caseDigest) throw new Error('这次协助还没有准备完成');
      await api.uploadRecoveryCaseTransfer(recoveryCase.id, {
        idempotencyKey: crypto.randomUUID(),
        caseDigest: recoveryCase.caseDigest,
        transfer,
      });
      toast('info', '恢复结果已提交，系统会自动完成恢复');
      if (onRecoveryChanged) await onRecoveryChanged();
      else await load();
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '恢复结果不匹配或已失效');
    } finally {
      setBusyId(null);
    }
  };
  const activeCases = cases.filter((entry) => ['waiting_for_target', 'pending_approval', 'approved', 'processing'].includes(entry.status));
  const recoveryReady = recoveryWorkspace === null
    || recoveryWorkspace.keys.some((key) => key.status === 'active');
  if (loading) return <LoadingState label="正在查看恢复协助…" />;
  return (
    <section className={styles.adminSection} aria-label="恢复协助">
      <h2>发起恢复协助</h2>
      <p>同事忘记主密码或交接中断时，由管理员在这里发起。一次协助覆盖其仍然有效的原有权限，不需要逐个密码库操作。</p>
      {!recoveryReady && <div className={styles.notice}>企业恢复尚未准备完成，请先打开“准备恢复”完成设置。</div>}
      <form className={styles.resetForm} onSubmit={create}>
        <label htmlFor="recovery-target-user">需要帮助的同事</label>
        <UserPicker
          inputId="recovery-target-user"
          value={targetUserId}
          onChange={setTargetUserId}
          excludeIds={[currentUserId, ...activeCases.map((entry) => entry.targetUserId)]}
          placeholder="搜索姓名、拼音或域账号"
          label="需要帮助的同事"
          disabled={!recoveryReady || busyId !== null}
        />
        <label htmlFor="recovery-case-kind">遇到的问题</label>
        <select id="recovery-case-kind" value={kind} onChange={(event) => setKind(event.target.value as EnterpriseRecoveryCase['kind'])}>
          <option value="forgot_password">忘记主密码</option>
          <option value="interrupted_handoff">已有权限，但交接中断后打不开</option>
        </select>
        <button className={styles.primary} type="submit" disabled={!recoveryReady || !targetUserId || busyId !== null}>
          {busyId === 'create' ? '正在发起…' : '发起恢复协助'}
        </button>
      </form>
      <h2>正在处理</h2>
      {activeCases.length === 0 && showEmpty && <div className={styles.emptyState}>当前没有进行中的恢复协助。</div>}
      {activeCases.map((recoveryCase) => {
        const approvedByMe = recoveryCase.approvalUserIds.includes(currentUserId);
        const canApprove = recoveryCase.status === 'pending_approval' && !approvedByMe;
        const unresolved = recoveryCase.items.length - recoveryCase.resolvedItemCount - recoveryCase.skippedItemCount;
        return (
          <div className={styles.recoveryGroup} key={recoveryCase.id}>
            <strong>{recoveryCase.targetDisplayName} · {recoveryCase.kind === 'forgot_password' ? '忘记主密码' : '交接中断'}</strong>
            <span>{recoveryCaseStatusText(recoveryCase)} · 原有密码库 {recoveryCase.items.length} 个</span>
            {canApprove && (
              <button type="button" disabled={busyId !== null} onClick={() => void approve(recoveryCase)}>
                {busyId === recoveryCase.id ? '正在确认…' : '确认身份并同意协助'}
              </button>
            )}
            {recoveryCase.status === 'pending_approval' && approvedByMe && <div className={styles.notice}>你已确认，等待另一位管理员。</div>}
            {['approved', 'processing'].includes(recoveryCase.status) && unresolved > 0 && !recoveryCase.hasOfflineResult && (
              <>
                <div className={styles.boundary}>最后一步：下载本案件的 JSON 文件，带到断网电脑，在恢复向导中选择“处理恢复案件”（避免恢复材料接触服务器或网络），再把生成的结果提交回来。</div>
                <div className={styles.actions}>
                  <button type="button" disabled={busyId !== null} onClick={() => void downloadPackage(recoveryCase)}>
                    {busyId === `download:${recoveryCase.id}` ? '正在准备…' : '下载案件文件'}
                  </button>
                  <label className={styles.secondary}>
                    提交恢复结果
                    <input
                      type="file"
                      accept="application/json,.json"
                      hidden
                      disabled={busyId !== null}
                      onChange={(event) => {
                        const file = event.target.files?.[0];
                        if (file) void uploadTransfer(recoveryCase, file);
                        event.target.value = '';
                      }}
                    />
                  </label>
                </div>
              </>
            )}
            {recoveryCase.hasOfflineResult && <div className={styles.notice}>离线处理已完成，系统正在自动完成恢复。</div>}
          </div>
        );
      })}
    </section>
  );
}

function recoveryCaseStatusText(recoveryCase: EnterpriseRecoveryCase): string {
  if (recoveryCase.status === 'waiting_for_target') return '等待用户设置新主密码';
  if (recoveryCase.status === 'pending_approval') return `管理员已确认 ${recoveryCase.approvalUserIds.length}/2 人`;
  const unresolved = recoveryCase.items.length - recoveryCase.resolvedItemCount - recoveryCase.skippedItemCount;
  if (['approved', 'processing'].includes(recoveryCase.status) && unresolved > 0 && !recoveryCase.hasOfflineResult) {
    return '两人已确认，等待完成最后一步';
  }
  if (recoveryCase.status === 'approved') return '两人已确认，正在继续处理';
  if (recoveryCase.status === 'processing') return '正在恢复原有访问';
  if (recoveryCase.status === 'completed') return '已经完成';
  if (recoveryCase.status === 'completed_with_skips') return '已完成，失效权限已跳过';
  if (recoveryCase.status === 'expired') return '已过期';
  return '已取消';
}

function downloadJson(fileName: string, value: unknown): void {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  URL.revokeObjectURL(url);
}

function MigrationPanel({ onLoggedOut }: { onLoggedOut: () => void }) {
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
        ? '这些个人密码库暂时打不开。在恢复完成前，系统不会返回对应条目；账号登录成功也不能代替密码库解锁。'
        : '移除成员、降低权限或撤销设备后，系统会更新密码库的访问保护。完成前暂时不能修改，避免旧权限继续获得新内容。'}</p>
      {pending.length > 0 && (
        <div className={styles.boundary}>对方已经看过或离线保存的旧内容无法远程抹除；这次安全更新只会阻止其继续获得后续内容。</div>
      )}
      {recoveryPending.map((state) => (
        <div className={styles.pendingVault} key={`recovery:${state.vaultId}`}>
          <strong>密码库 {state.vaultId.slice(0, 8)} · 需要企业恢复</strong>
          <span>请在公司群里联系管理员发起恢复协助。两位管理员确认后，系统只会恢复你原本拥有的权限，管理员不能借此查看或接管。</span>
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
