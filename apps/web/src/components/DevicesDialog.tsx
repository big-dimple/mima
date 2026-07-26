import { useEffect, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { KeyRound, LockKeyhole, MonitorSmartphone, RefreshCw, Trash2, X } from 'lucide-react';
import type { CryptoDevice } from '@mima/contracts';
import { useApp } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import { ActionButton } from './ActionButton.tsx';
import { IconButton } from './IconButton.tsx';
import dialogStyles from './dialog.module.css';
import styles from './DevicesDialog.module.css';

const DEVICE_TYPE_LABEL: Record<CryptoDevice['deviceType'], string> = {
  web: '工作台浏览器',
  extension: '浏览器扩展（独立授权）',
  desktop: '桌面客户端',
  mobile: '移动设备',
};

export function DevicesDialog() {
  const { zeroKnowledge } = useApp();
  const open = useUi((state) => state.devicesOpen);
  const setOpen = useUi((state) => state.setDevicesOpen);
  const toast = useUi((state) => state.toast);
  const [devices, setDevices] = useState<CryptoDevice[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  const [rotationOpen, setRotationOpen] = useState(false);
  const [rotating, setRotating] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);
  const [passwordChangeOpen, setPasswordChangeOpen] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);
  const [passwordChangeError, setPasswordChangeError] = useState<string | null>(null);
  const currentPasswordRef = useRef<HTMLInputElement>(null);
  const newPasswordRef = useRef<HTMLInputElement>(null);
  const confirmPasswordRef = useRef<HTMLInputElement>(null);
  const securityMutationBusy = revoking !== null || rotating || changingPassword;

  const load = async () => {
    setDevices(null);
    setError(null);
    try {
      setDevices(await zeroKnowledge.listDevices());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '设备列表加载失败');
    }
  };

  useEffect(() => {
    if (open) void load();
    else {
      setDevices(null);
      setError(null);
      setRevoking(null);
      setRotationOpen(false);
      setPasswordChangeOpen(false);
      setPasswordChangeError(null);
      if (passwordRef.current) passwordRef.current.value = '';
      clearPasswordChangeInputs();
    }
  }, [open]);

  const revoke = async (device: CryptoDevice) => {
    const current = device.id === zeroKnowledge.currentDeviceId;
    const extension = device.deviceType === 'extension';
    const confirmed = await useUi.getState().requestConfirm({
      title: current ? '撤销当前工作台' : extension ? '撤销浏览器扩展' : '撤销设备',
      body: current
        ? '撤销后此浏览器会立即锁定并退出，本地离线数据也会删除。普通撤销不能处理主密码或账号安全信息泄露；怀疑泄露时还必须在另一台可信设备上轮换身份密钥。'
        : extension
          ? '撤销后，这个浏览器扩展会立即失去同步和填充权限，本地授权与离线数据会在下次联网时清除。重新使用必须再次配对；当前工作台不受影响。'
          : '普通撤销会阻止这个设备继续同步，并安全更新受影响密码库的访问。它不能抹掉已保存内容，也不能处理主密码或账号安全信息泄露；怀疑泄露时请改用“轮换身份密钥”。',
      confirmText: current ? '撤销当前工作台' : extension ? '撤销扩展' : '撤销设备',
      cancelText: '取消',
      danger: true,
    });
    if (!confirmed) return;
    setRevoking(device.id);
    try {
      await zeroKnowledge.revokeDevice(device);
      setOpen(false);
      toast(
        'warn',
        extension
          ? '浏览器扩展已撤销；重新使用前必须再次配对'
          : '设备已撤销；怀疑主密码或账号安全信息泄露时，还必须轮换身份密钥',
      );
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '设备撤销失败');
    } finally {
      setRevoking(null);
    }
  };

  const rotateIdentity = async (event: React.FormEvent) => {
    event.preventDefault();
    const confirmed = await useUi.getState().requestConfirm({
      title: '轮换身份密钥',
      body: '这会撤销其他设备和扩展，清除尚未同步的本地修改，并暂停相关密码库的修改，直到访问安全更新完成。旧设备已经保存的内容无法远程抹除。',
      confirmText: '继续轮换',
      cancelText: '取消',
      danger: true,
    });
    if (!confirmed) return;
    const mainPassword = passwordRef.current?.value ?? '';
    if (!mainPassword) return;
    setRotating(true);
    try {
      const outcome = await zeroKnowledge.rotateIdentity(mainPassword);
      setOpen(false);
      toast(
        outcome.localCachePersisted ? 'warn' : 'error',
        outcome.localCachePersisted
          ? `身份密钥已轮换，已撤销 ${outcome.revokedDeviceCount} 台其他设备；请完成密码库安全更新。`
          : '身份密钥已在服务器生效，但本地数据保存失败。请勿关闭页面，并完成密码库安全更新。',
      );
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '身份密钥轮换失败');
    } finally {
      if (passwordRef.current) passwordRef.current.value = '';
      setRotating(false);
    }
  };

  const changeMainPassword = async (event: React.FormEvent) => {
    event.preventDefault();
    const currentPassword = currentPasswordRef.current?.value ?? '';
    const newPassword = newPasswordRef.current?.value ?? '';
    const confirmation = confirmPasswordRef.current?.value ?? '';
    if (!currentPassword || !newPassword || !confirmation) return;
    setPasswordChangeError(null);
    setChangingPassword(true);
    try {
      const outcome = await zeroKnowledge.changeMainPassword(
        currentPassword,
        newPassword,
        confirmation,
      );
      setPasswordChangeOpen(false);
      setPasswordChangeError(null);
      toast(
        outcome.localCachePersisted ? 'info' : 'warn',
        outcome.localCachePersisted
          ? '主密码已更新；其他已联网设备会立即锁定，离线设备下次联网后锁定并改用新主密码。'
          : '主密码已更新，但本机离线数据保存失败并已删除，下次需要联网解锁。',
      );
    } catch (caught) {
      const message = caught instanceof Error ? caught.message : '主密码修改失败';
      setPasswordChangeError(message);
      toast('error', message);
    } finally {
      clearPasswordChangeInputs();
      setChangingPassword(false);
    }
  };

  const clearPasswordChangeInputs = () => {
    if (currentPasswordRef.current) currentPasswordRef.current.value = '';
    if (newPasswordRef.current) newPasswordRef.current.value = '';
    if (confirmPasswordRef.current) confirmPasswordRef.current.value = '';
  };

  if (!open) return null;
  return (
    <Dialog.Root open onOpenChange={(nextOpen) => {
      if (!securityMutationBusy) setOpen(nextOpen);
    }}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={[dialogStyles.content, styles.content].join(' ')} aria-describedby={undefined}>
          <Dialog.Title className={dialogStyles.title}>已授权设备</Dialog.Title>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭" disabled={securityMutationBusy}><X size={16} /></button>
          </Dialog.Close>
          <div className={styles.toolbar}>
            <span>工作台与浏览器扩展是两项独立授权。正常升级或重启不会要求重新配对；撤销扩展后才需要重新配对。</span>
            <IconButton label="刷新设备列表" disabled={securityMutationBusy} onClick={() => void load()}>
              <RefreshCw size={15} />
            </IconButton>
          </div>
          {error && <ErrorState message={error} onRetry={() => void load()} />}
          {!error && devices === null && <LoadingState label="正在加载设备…" />}
          <div className={styles.list}>
            {devices?.map((device) => {
              const current = device.id === zeroKnowledge.currentDeviceId;
              return (
                <div className={styles.device} key={device.id}>
                  <MonitorSmartphone size={18} aria-hidden />
                  <div className={styles.deviceBody}>
                    <div className={styles.deviceTitle}>
                      {DEVICE_TYPE_LABEL[device.deviceType]}
                      {current && <span>当前工作台</span>}
                      {device.revokedAt && <span className={styles.revoked}>已撤销</span>}
                    </div>
                    <div className={styles.deviceMeta}>
                      授权于 {formatTime(device.trustedAt)} · 最近使用 {device.lastSeenAt ? formatTime(device.lastSeenAt) : '暂无'}
                    </div>
                    <code>{device.signingPublicKey.slice(0, 12)}…</code>
                  </div>
                  {!device.revokedAt && (
                    <IconButton
                      label={device.deviceType === 'extension' ? '撤销浏览器扩展' : current ? '撤销当前工作台' : '撤销设备'}
                      danger
                      disabled={securityMutationBusy}
                      onClick={() => void revoke(device)}
                    >
                      <Trash2 size={15} />
                    </IconButton>
                  )}
                </div>
              );
            })}
          </div>
          <section className={styles.rotation}>
            <div>
              <strong>修改主密码</strong>
              <p>只更新主密码对账号解锁信息的保护，不会重写全部条目或撤销设备。已联网设备会立即锁定；离线设备下次联网前，旧主密码仍可能打开其本地旧数据。怀疑设备或账号安全信息泄露时请使用身份密钥轮换。</p>
            </div>
            {!passwordChangeOpen ? (
              <button
                type="button"
                className={styles.passwordToggle}
                disabled={securityMutationBusy}
                onClick={() => {
                  setPasswordChangeError(null);
                  setPasswordChangeOpen(true);
                }}
              >
                <LockKeyhole size={15} aria-hidden />
                修改主密码
              </button>
            ) : (
              <form className={styles.passwordForm} aria-busy={changingPassword} onSubmit={changeMainPassword}>
                <div className={styles.passwordFields}>
                  <label htmlFor="current-main-password">当前主密码</label>
                  <input
                    id="current-main-password"
                    ref={currentPasswordRef}
                    type="password"
                    autoComplete="current-password"
                    required
                    maxLength={256}
                    disabled={securityMutationBusy}
                    autoFocus
                  />
                  <label htmlFor="new-main-password-settings">新主密码</label>
                  <input
                    id="new-main-password-settings"
                    ref={newPasswordRef}
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={12}
                    maxLength={256}
                    disabled={securityMutationBusy}
                  />
                  <label htmlFor="confirm-main-password-settings">再次输入新主密码</label>
                  <input
                    id="confirm-main-password-settings"
                    ref={confirmPasswordRef}
                    type="password"
                    autoComplete="new-password"
                    required
                    minLength={12}
                    maxLength={256}
                    disabled={securityMutationBusy}
                  />
                </div>
                {passwordChangeError && (
                  <div className={styles.passwordError} role="alert">{passwordChangeError}</div>
                )}
                <div className={styles.passwordActions}>
                  <ActionButton
                    label="取消"
                    variant="secondary"
                    disabled={securityMutationBusy}
                    onClick={() => {
                      clearPasswordChangeInputs();
                      setPasswordChangeError(null);
                      setPasswordChangeOpen(false);
                    }}
                  />
                  <ActionButton
                    label={changingPassword ? '正在更新…' : '验证并更新'}
                    type="submit"
                    disabled={securityMutationBusy}
                  />
                </div>
              </form>
            )}
          </section>
          <section className={styles.rotation}>
            <div>
              <strong>怀疑设备泄露？</strong>
              <p>轮换身份密钥会为账号和当前设备建立全新的安全信息，并撤销其他设备。此操作不同于普通撤销。</p>
            </div>
            {!rotationOpen ? (
              <button
                type="button"
                className={styles.rotationToggle}
                disabled={securityMutationBusy}
                onClick={() => setRotationOpen(true)}
              >
                <KeyRound size={15} aria-hidden />
                轮换身份密钥
              </button>
            ) : (
              <form className={styles.rotationForm} onSubmit={rotateIdentity}>
                <label htmlFor="identity-rotation-password">主密码</label>
                <div>
                  <input
                    id="identity-rotation-password"
                    ref={passwordRef}
                    type="password"
                    autoComplete="current-password"
                    required
                    maxLength={256}
                    disabled={securityMutationBusy}
                    autoFocus
                  />
                  <button type="submit" disabled={securityMutationBusy}>{rotating ? '轮换中…' : '验证并轮换'}</button>
                </div>
              </form>
            )}
          </section>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function formatTime(value: string): string {
  return new Date(value).toLocaleString('zh-CN', { hour12: false });
}
