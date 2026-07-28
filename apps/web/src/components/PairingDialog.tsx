import { useEffect, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { Copy, Download, LoaderCircle, RefreshCw, X } from 'lucide-react';
import { useApp } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { copyWithTimedClear } from '../utils/clipboard.ts';
import { ActionButton } from './ActionButton.tsx';
import type { ExtensionEnrollment } from '@mima/client-core';
import { LoadingState } from './AsyncState.tsx';
import dialogStyles from './dialog.module.css';
import styles from './PairingDialog.module.css';

/** 浏览器扩展配对：生成 120 秒一次性配对码。 */
export function PairingDialog() {
  const { api, zeroKnowledge } = useApp();
  const open = useUi((s) => s.pairingOpen);
  const setOpen = useUi((s) => s.setPairingOpen);
  const [code, setCode] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<number>(0);
  const [remaining, setRemaining] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [enrollment, setEnrollment] = useState<ExtensionEnrollment | null>(null);
  const [approving, setApproving] = useState(false);
  const [approved, setApproved] = useState(false);
  const [pairingExpired, setPairingExpired] = useState(false);
  const openedRef = useRef(false);
  const requestRef = useRef(0);
  const toast = useUi((s) => s.toast);

  const generate = async () => {
    const requestId = ++requestRef.current;
    setBusy(true);
    setError(null);
    try {
      const res = await api.createPairingCode();
      if (requestId !== requestRef.current) return;
      const nextExpiresAt = new Date(res.expiresAt).getTime();
      setCode(res.code);
      setEnrollment(null);
      setApproved(false);
      setPairingExpired(false);
      setExpiresAt(nextExpiresAt);
      setRemaining(Math.max(0, Math.ceil((nextExpiresAt - Date.now()) / 1000)));
    } catch (err) {
      if (requestId === requestRef.current) {
        setError(err instanceof Error ? err.message : '生成失败');
      }
    } finally {
      if (requestId === requestRef.current) setBusy(false);
    }
  };

  useEffect(() => {
    if (open && !openedRef.current) {
      openedRef.current = true;
      void generate();
    } else if (!open) {
      openedRef.current = false;
      requestRef.current += 1;
      setCode(null);
      setRemaining(0);
      setError(null);
      setBusy(false);
      setEnrollment(null);
      setApproved(false);
      setPairingExpired(false);
    }
  }, [open]);

  useEffect(() => {
    if (!code) return;
    const t = setInterval(() => {
      setRemaining(Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000)));
    }, 500);
    return () => clearInterval(t);
  }, [code, expiresAt]);

  useEffect(() => {
    if (!open || !code || approved || pairingExpired) return;
    let stopped = false;
    const poll = async () => {
      try {
        const value = await api.extensionPairingStatus(code);
        if (stopped) return;
        if (value.status === 'claimed' && value.enrollment) {
          setEnrollment(value.enrollment);
          return;
        }
        if (value.status === 'expired') setPairingExpired(true);
      } catch {
        // 配对码仍可显示；下一轮继续等待扩展提交设备公钥。
      }
    };
    void poll();
    const timer = setInterval(() => void poll(), 1_500);
    return () => {
      stopped = true;
      clearInterval(timer);
    };
  }, [api, open, code, approved, pairingExpired]);

  const copyCode = async () => {
    if (!code || remaining <= 0) return;
    try {
      await copyWithTimedClear(code);
      toast('info', '配对码已复制，30 秒后将尽力清理剪贴板');
    } catch {
      toast('error', '无法写入剪贴板，请手动输入配对码');
    }
  };

  const approve = async () => {
    if (!enrollment) return;
    setApproving(true);
    try {
      await zeroKnowledge.approveExtensionEnrollment(enrollment);
      setApproved(true);
      setEnrollment(null);
      toast('info', '扩展已批准，等待扩展完成连接');
    } catch (caught) {
      toast('error', caught instanceof Error ? caught.message : '扩展设备批准失败');
    } finally {
      setApproving(false);
    }
  };

  if (!open) return null;

  return (
    <Dialog.Root open onOpenChange={setOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={dialogStyles.content} aria-describedby={undefined}>
          <Dialog.Title className={dialogStyles.title}>配对浏览器扩展</Dialog.Title>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭"><X size={16} /></button>
          </Dialog.Close>
          <a
            className={styles.download}
            href="/downloads/mima-extension-0.2.0.zip"
            download
          >
            <Download size={16} aria-hidden />
            下载 Chrome / Edge 扩展安装包
          </a>
          <ol className={styles.steps}>
            <li>解压安装包，在扩展管理页开启开发者模式并选择“加载已解压的扩展”。</li>
            <li>打开“Mima”侧边栏，也可以按 <kbd>Ctrl+Shift+Space</kbd>。</li>
            <li>复制或手动输入下方的一次性配对码。</li>
            <li>两边显示的设备指纹完全一致后，再在这里批准。</li>
          </ol>
          <p className={styles.note}>
            新扩展不需要重复输入主密码。批准一次后，正常升级、关闭或重启浏览器都会由已解锁工作台恢复连接；只有主动撤销或解除配对才需要重新配对。
          </p>
          {error && <div className={styles.error} role="alert">{error}</div>}
          {busy && !code && <LoadingState label="正在生成配对码…" />}
          {code && (
            <div className={styles.codeBox} aria-live="polite">
              <div className={styles.codeDetails}>
                <span className={styles.code}>{code}</span>
                <span className={remaining > 0 ? styles.timer : styles.expired} role="timer">
                  {remaining > 0
                    ? `${remaining}s 内有效 · 一次性`
                    : enrollment
                      ? '配对码已领取，请在设备申请失效前完成核对'
                      : '已过期'}
                </span>
              </div>
              <ActionButton
                label="复制配对码"
                icon={<Copy size={16} />}
                onClick={() => void copyCode()}
                disabled={busy || remaining <= 0}
              />
            </div>
          )}
          {enrollment && (
            <div className={styles.approvalBox}>
              <span className={styles.approvalLabel}>待批准设备指纹</span>
              <code className={styles.fingerprint}>{enrollment.fingerprint}</code>
              <p>请逐组核对扩展侧边栏中的 8 组指纹。任何一组不同都不要批准。</p>
              <ActionButton
                label={approving ? '批准中…' : '指纹一致，批准此设备'}
                onClick={() => void approve()}
                disabled={approving}
              />
            </div>
          )}
          {approved && (
            <div className={styles.approved} role="status">
              扩展已获准连接。回到仍打开的扩展检查结果即可，无需再次输入主密码。
            </div>
          )}
          <ActionButton
            variant="secondary"
            label={busy ? '生成中…' : '重新生成'}
            icon={busy ? <LoaderCircle className={styles.spin} size={16} /> : <RefreshCw size={16} />}
            onClick={() => void generate()}
            disabled={busy}
          />
          <p className={styles.note}>
            扩展的解锁信息只保存在此浏览器。批准后，工作台会安全地帮助这个扩展解锁；主密码不会离开当前设备，也不会发送到服务端。
          </p>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
