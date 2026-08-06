import { useEffect, useRef, useState, type ReactNode } from 'react';
import { HardDrive, KeyRound, LogOut, PlugZap, Wifi, WifiOff, Loader2, BookOpen, UsersRound, ShieldAlert, MonitorSmartphone, MoreHorizontal } from 'lucide-react';
import { useApp, useMeta } from '../state/app-context.ts';
import type { LocalAccessReason } from '../state/local-access.ts';
import { useUi } from '../state/ui-store.ts';
import { IconButton } from './IconButton.tsx';
import styles from './Header.module.css';

export function Header({
  localAccessReason = null,
  onLoggedOut,
}: {
  localAccessReason?: LocalAccessReason;
  onLoggedOut: () => void;
}) {
  const { actions, outbox } = useApp();
  const user = useMeta((s) => s.user);
  const connection = useMeta((s) => s.connection);
  const pendingCount = useMeta((s) => Object.keys(s.pendingItemIds).length);
  const setPairingOpen = useUi((s) => s.setPairingOpen);
  const setGuideOpen = useUi((s) => s.setGuideOpen);
  const setGroupsOpen = useUi((s) => s.setGroupsOpen);
  const setRecoveryOpen = useUi((s) => s.setRecoveryOpen);
  const setDevicesOpen = useUi((s) => s.setDevicesOpen);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const mobileMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!mobileMenuOpen) return;
    const closeOnOutside = (event: PointerEvent) => {
      if (!mobileMenuRef.current?.contains(event.target as Node)) setMobileMenuOpen(false);
    };
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setMobileMenuOpen(false);
    };
    document.addEventListener('pointerdown', closeOnOutside);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOnOutside);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [mobileMenuOpen]);

  const handleLogout = async () => {
    try {
      await actions.logout();
    } finally {
      onLoggedOut();
    }
  };

  return (
    <header className={styles.header}>
      <div className={styles.brand}>
        <KeyRound size={17} aria-hidden />
        <span>Mima</span>
      </div>
      <div className={styles.status}>
        {connection === 'online' && (
          <span className={styles.online} title="实时同步已连接">
            <Wifi size={14} aria-hidden /> 在线
          </span>
        )}
        {connection === 'connecting' && (
          <span className={styles.connecting}>
            <Loader2 size={14} className={styles.spin} aria-hidden /> 连接中
          </span>
        )}
        {connection === 'offline' && localAccessReason === 'session-expired' && (
          <span className={styles.local} title="账号登录已过期，当前只使用本机加密数据">
            <HardDrive size={14} aria-hidden /> 本机模式
          </span>
        )}
        {connection === 'offline' && localAccessReason !== 'session-expired' && (
          <span className={styles.offline}>
            <WifiOff size={14} aria-hidden /> 离线
          </span>
        )}
        {(pendingCount > 0 || outbox.size > 0) && (
          <span className={styles.pending}>待同步 {Math.max(pendingCount, outbox.size)}</span>
        )}
      </div>
      <div className={styles.spacer} />
      <span className={styles.user}>{user?.displayName}</span>
      <div className={styles.desktopActions}>
        <button className={styles.guideBtn} onClick={() => setGuideOpen(true)} data-tour="guide" aria-label="新手指南">
          <BookOpen size={15} aria-hidden />
          <span>新手指南</span>
        </button>
        <IconButton label="管理用户组" onClick={() => setGroupsOpen(true)}>
          <UsersRound size={16} />
        </IconButton>
        <IconButton label="配对浏览器扩展" onClick={() => setPairingOpen(true)} tour="pair-extension">
          <PlugZap size={16} />
        </IconButton>
        <IconButton label="企业恢复" onClick={() => setRecoveryOpen(true)}>
          <ShieldAlert size={16} />
        </IconButton>
        <IconButton label="已授权设备" onClick={() => setDevicesOpen(true)}>
          <MonitorSmartphone size={16} />
        </IconButton>
      </div>
      <div className={styles.mobileMenu} ref={mobileMenuRef}>
        <IconButton
          label="更多工具"
          active={mobileMenuOpen}
          tour="more-tools"
          ariaExpanded={mobileMenuOpen}
          onClick={() => setMobileMenuOpen((value) => !value)}
        >
          <MoreHorizontal size={17} />
        </IconButton>
        {mobileMenuOpen && (
          <div className={styles.mobileMenuPanel} role="group" aria-label="更多工具">
            <MenuCommand icon={<BookOpen size={16} />} label="新手指南" onClick={() => setGuideOpen(true)} />
            <MenuCommand icon={<UsersRound size={16} />} label="管理用户组" onClick={() => setGroupsOpen(true)} />
            <MenuCommand icon={<PlugZap size={16} />} label="配对浏览器扩展" onClick={() => setPairingOpen(true)} />
            <MenuCommand icon={<ShieldAlert size={16} />} label="企业恢复" onClick={() => setRecoveryOpen(true)} />
            <MenuCommand icon={<MonitorSmartphone size={16} />} label="已授权设备" onClick={() => setDevicesOpen(true)} />
          </div>
        )}
      </div>
      <IconButton label="退出登录" onClick={handleLogout} tour="logout">
        <LogOut size={16} />
      </IconButton>
    </header>
  );

  function MenuCommand({ icon, label, onClick }: { icon: ReactNode; label: string; onClick: () => void }) {
    return (
      <button
        type="button"
        onClick={() => {
          setMobileMenuOpen(false);
          onClick();
        }}
      >
        {icon}<span>{label}</span>
      </button>
    );
  }
}
