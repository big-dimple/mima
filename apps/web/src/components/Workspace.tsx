import { Suspense, lazy, useEffect, useRef, useState } from 'react';
import { ArrowLeft, GripVertical, PanelLeftOpen, X } from 'lucide-react';
import { useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { Header } from './Header.tsx';
import { VaultNav } from './VaultNav.tsx';
import { ItemList } from './ItemList.tsx';
import { ItemDetail } from './ItemDetail.tsx';
import { ConfirmDialog } from './ConfirmDialog.tsx';
import { TourPrompt } from './TourPrompt.tsx';
import { LoadingState } from './AsyncState.tsx';
import { GuideDialog } from './GuideDialog.tsx';
import { IconButton } from './IconButton.tsx';
import { LegacyKeyRetirementBanner } from './LegacyKeyRetirementBanner.tsx';
import { RecoveryCoverageBanner } from './RecoveryCoverageBanner.tsx';
import styles from './Workspace.module.css';

const MembersDialog = lazy(() => import('./MembersDialog.tsx').then((m) => ({ default: m.MembersDialog })));
const AuditDialog = lazy(() => import('./AuditDialog.tsx').then((m) => ({ default: m.AuditDialog })));
const PairingDialog = lazy(() => import('./PairingDialog.tsx').then((m) => ({ default: m.PairingDialog })));
const OnboardingTour = lazy(() => import('./OnboardingTour.tsx').then((m) => ({ default: m.OnboardingTour })));
const GroupsDialog = lazy(() => import('./GroupsDialog.tsx').then((m) => ({ default: m.GroupsDialog })));
const RecoveryDialog = lazy(() => import('./RecoveryDialog.tsx').then((m) => ({ default: m.RecoveryDialog })));
const DevicesDialog = lazy(() => import('./DevicesDialog.tsx').then((m) => ({ default: m.DevicesDialog })));
const LegacyKeyRetirementDialog = lazy(() => import('./LegacyKeyRetirementDialog.tsx').then((m) => ({ default: m.LegacyKeyRetirementDialog })));

const LAYOUT_KEY = 'mima.layout.v3';
const PREVIOUS_LAYOUT_KEY = 'mima.layout.v2';
const LEGACY_LAYOUT_KEY = 'mima.layout.v1';
const LEGACY_NAV_MIN_WIDTH = 200;
const NAV_MIN_WIDTH = 280;
const NAV_MAX_WIDTH = 640;
const LIST_MIN_WIDTH = 300;
const LIST_MAX_WIDTH = 520;
const DETAIL_MIN_WIDTH = 480;
const SEPARATORS_WIDTH = 24;
const DEFAULT_LAYOUT = { navWidth: 384, listWidth: 420 };
type WorkspaceLayout = typeof DEFAULT_LAYOUT;
type ViewportMode = 'desktop' | 'tablet' | 'mobile';

export function Workspace({ onLoggedOut }: { onLoggedOut: () => void }) {
  const connection = useMeta((s) => s.connection);
  const lastRevokedVaultId = useMeta((s) => s.lastRevokedVaultId);
  const selectedVaultId = useUi((s) => s.selectedVaultId);
  const selectVault = useUi((s) => s.selectVault);
  const guideOpen = useUi((s) => s.guideOpen);
  const setGuideOpen = useUi((s) => s.setGuideOpen);
  const startTour = useUi((s) => s.startTour);
  const toast = useUi((s) => s.toast);
  const selectedItemId = useUi((s) => s.selectedItemId);
  const editing = useUi((s) => s.editing);
  const [preferredLayout, setPreferredLayout] = useState(readLayoutPreference);
  const preferredLayoutRef = useRef(preferredLayout);
  const [viewportWidth, setViewportWidth] = useState(() => typeof window === 'undefined' ? 1440 : window.innerWidth);
  const layout = clampLayout(preferredLayout, viewportWidth);
  const [mode, setMode] = useState<ViewportMode>(viewportMode);
  const [navOpen, setNavOpen] = useState(false);

  useEffect(() => {
    preferredLayoutRef.current = preferredLayout;
  }, [preferredLayout]);

  useEffect(() => {
    const onResize = () => {
      setMode(viewportMode());
      setViewportWidth(window.innerWidth);
    };
    const onStorage = (event: StorageEvent) => {
      if (event.key === LAYOUT_KEY) setPreferredLayout(readLayoutPreference());
    };
    window.addEventListener('resize', onResize);
    window.addEventListener('storage', onStorage);
    return () => {
      window.removeEventListener('resize', onResize);
      window.removeEventListener('storage', onStorage);
    };
  }, []);

  useEffect(() => setNavOpen(false), [selectedVaultId]);

  // 权限被撤销的库若正被查看，回到"全部"并提示
  useEffect(() => {
    if (lastRevokedVaultId && selectedVaultId === lastRevokedVaultId) {
      selectVault('all');
      toast('warn', '你对当前库的访问权限已被撤销');
    }
  }, [lastRevokedVaultId, selectedVaultId, selectVault, toast]);

  return (
    <div className={styles.shell}>
      <Header onLoggedOut={onLoggedOut} />
      {connection !== 'online' && (
        <div className={styles.offlineBanner} role="status">
          {connection === 'connecting' ? '正在重新连接…' : '当前离线：可使用此浏览器保存的数据；修改会先在本机保护好，恢复网络后自动同步。'}
        </div>
      )}
      <LegacyKeyRetirementBanner />
      <RecoveryCoverageBanner />
      {mode === 'desktop' ? (
        <div
          className={styles.panes}
          style={{
            '--nav-width': `${layout.navWidth}px`,
            '--list-width': `${layout.listWidth}px`,
          } as React.CSSProperties}
        >
          <div className={styles.navPane}><VaultNav /></div>
          <PaneSeparator
            label="调整密码库导航宽度"
            value={layout.navWidth}
            preferenceValue={preferredLayout.navWidth}
            min={NAV_MIN_WIDTH}
            max={NAV_MAX_WIDTH}
            tour="nav-resizer"
            onChange={(value) => setPreferredLayout((current) => normalizeLayout({ ...current, navWidth: value }))}
            onCommit={(value) => {
              const next = normalizeLayout({ ...preferredLayoutRef.current, navWidth: value });
              preferredLayoutRef.current = next;
              setPreferredLayout(next);
              persistLayoutPreference(next);
            }}
            onReset={() => {
              setPreferredLayout(DEFAULT_LAYOUT);
              persistLayoutPreference(DEFAULT_LAYOUT);
            }}
          />
          <div className={styles.listPane}><ItemList /></div>
          <PaneSeparator
            label="调整凭证列表宽度"
            value={layout.listWidth}
            preferenceValue={preferredLayout.listWidth}
            min={LIST_MIN_WIDTH}
            max={LIST_MAX_WIDTH}
            onChange={(value) => setPreferredLayout((current) => normalizeLayout({ ...current, listWidth: value }))}
            onCommit={(value) => {
              const next = normalizeLayout({ ...preferredLayoutRef.current, listWidth: value });
              preferredLayoutRef.current = next;
              setPreferredLayout(next);
              persistLayoutPreference(next);
            }}
            onReset={() => {
              setPreferredLayout(DEFAULT_LAYOUT);
              persistLayoutPreference(DEFAULT_LAYOUT);
            }}
          />
          <div className={styles.detailPane}><ItemDetail /></div>
        </div>
      ) : (
        <div className={styles.compactWorkspace}>
          <div className={styles.compactToolbar}>
            {mode === 'mobile' && (selectedItemId || editing) ? (
              <IconButton label="返回凭证列表" onClick={() => {
                useUi.getState().selectItem(null);
                useUi.getState().setEditing(null);
              }}>
                <ArrowLeft size={17} />
              </IconButton>
            ) : (
              <IconButton label="打开密码库导航" onClick={() => setNavOpen(true)} tour="open-vault-nav">
                <PanelLeftOpen size={17} />
              </IconButton>
            )}
            <span>{mode === 'mobile' && (selectedItemId || editing) ? '凭证详情' : '密码库'}</span>
          </div>
          <div className={mode === 'tablet' ? styles.compactPanes : styles.singlePane}>
            {mode === 'tablet' ? (
              <>
                <ItemList />
                <div className={styles.detailPane}><ItemDetail /></div>
              </>
            ) : selectedItemId || editing ? (
              <div className={styles.detailPane}><ItemDetail /></div>
            ) : (
              <ItemList />
            )}
          </div>
          {navOpen && (
            <div className={styles.drawerLayer}>
              <button className={styles.drawerBackdrop} aria-label="关闭密码库导航" onClick={() => setNavOpen(false)} />
              <div className={styles.drawer} role="dialog" aria-modal="true" aria-label="密码库导航">
                <div className={styles.drawerHeader}>
                  <strong>密码库</strong>
                  <IconButton label="关闭密码库导航" onClick={() => setNavOpen(false)}><X size={16} /></IconButton>
                </div>
                <VaultNav />
              </div>
            </div>
          )}
        </div>
      )}
      <ConfirmDialog />
      <Suspense fallback={<LoadingState variant="overlay" label="正在加载界面…" />}>
        <MembersDialog />
        <AuditDialog />
        <PairingDialog />
        <GroupsDialog />
        <RecoveryDialog />
        <DevicesDialog />
        <LegacyKeyRetirementDialog />
        <GuideDialog open={guideOpen} onClose={() => setGuideOpen(false)} onStartTour={startTour} />
        <OnboardingTour />
      </Suspense>
      <TourPrompt />
    </div>
  );
}

function PaneSeparator({
  label,
  value,
  preferenceValue,
  min,
  max,
  onChange,
  onCommit,
  onReset,
  tour,
}: {
  label: string;
  value: number;
  preferenceValue: number;
  min: number;
  max: number;
  onChange: (value: number) => void;
  onCommit: (value: number) => void;
  onReset: () => void;
  tour?: string;
}) {
  const startDrag = (event: React.PointerEvent<HTMLDivElement>) => {
    event.preventDefault();
    const startX = event.clientX;
    const startValue = preferenceValue;
    let currentValue = startValue;
    const move = (pointerEvent: PointerEvent) => {
      currentValue = startValue + pointerEvent.clientX - startX;
      onChange(currentValue);
    };
    const cleanup = () => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', finish);
      window.removeEventListener('keydown', keydown);
      document.body.classList.remove('isResizing');
    };
    const finish = () => {
      cleanup();
      onCommit(currentValue);
    };
    const keydown = (keyboardEvent: KeyboardEvent) => {
      if (keyboardEvent.key === 'Escape') {
        onChange(startValue);
        cleanup();
      }
    };
    document.body.classList.add('isResizing');
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', finish);
    window.addEventListener('keydown', keydown);
  };

  return (
    <div
      className={styles.separator}
      role="separator"
      aria-label={label}
      aria-orientation="vertical"
      aria-valuemin={min}
      aria-valuemax={max}
      aria-valuenow={Math.round(value)}
      data-tour={tour}
      tabIndex={0}
      onPointerDown={startDrag}
      onDoubleClick={onReset}
      onKeyDown={(event) => {
        const step = event.shiftKey ? 48 : 16;
        let next: number;
        if (event.key === 'ArrowLeft') next = preferenceValue - step;
        else if (event.key === 'ArrowRight') next = preferenceValue + step;
        else if (event.key === 'Home') next = min;
        else if (event.key === 'End') next = max;
        else return;
        event.preventDefault();
        onChange(next);
        onCommit(next);
      }}
    >
      <GripVertical size={14} aria-hidden />
    </div>
  );
}

function viewportMode(): ViewportMode {
  if (typeof window === 'undefined') return 'desktop';
  if (window.innerWidth < 768) return 'mobile';
  return window.innerWidth < 1120 ? 'tablet' : 'desktop';
}

export function readLayoutPreference(): WorkspaceLayout {
  if (typeof window === 'undefined') return DEFAULT_LAYOUT;
  try {
    const current = parseLayout(localStorage.getItem(LAYOUT_KEY));
    if (current) return normalizeLayout(current);

    const previous = parseLayout(localStorage.getItem(PREVIOUS_LAYOUT_KEY));
    if (previous) {
      const next = isPreviousAutomaticLayout(previous) ? DEFAULT_LAYOUT : normalizeLayout(previous);
      persistLayoutPreference(next);
      return next;
    }

    const legacy = parseLayout(localStorage.getItem(LEGACY_LAYOUT_KEY));
    if (legacy) {
      const next = normalizeLayout({
        navWidth: legacy.navWidth <= LEGACY_NAV_MIN_WIDTH ? DEFAULT_LAYOUT.navWidth : legacy.navWidth,
        listWidth: legacy.listWidth,
      });
      persistLayoutPreference(next);
      return next;
    }
    persistLayoutPreference(DEFAULT_LAYOUT);
    return DEFAULT_LAYOUT;
  } catch {
    return DEFAULT_LAYOUT;
  }
}

function parseLayout(value: string | null): WorkspaceLayout | null {
  if (!value) return null;
  const parsed = JSON.parse(value) as Partial<WorkspaceLayout>;
  const navWidth = Number(parsed.navWidth);
  const listWidth = Number(parsed.listWidth);
  return Number.isFinite(navWidth) && navWidth > 0 && Number.isFinite(listWidth) && listWidth > 0
    ? { navWidth, listWidth }
    : null;
}

export function isPreviousAutomaticLayout(layout: WorkspaceLayout): boolean {
  return (
    layout.listWidth === LIST_MIN_WIDTH && layout.navWidth >= NAV_MIN_WIDTH && layout.navWidth <= 320
  ) || (
    layout.navWidth === 320 && layout.listWidth >= LIST_MIN_WIDTH && layout.listWidth <= 360
  );
}

function persistLayoutPreference(layout: WorkspaceLayout): void {
  try {
    localStorage.setItem(LAYOUT_KEY, JSON.stringify(normalizeLayout(layout)));
  } catch {
    // Private browsing may disable localStorage; resizing still works for this page.
  }
}

export function normalizeLayout(layout: WorkspaceLayout): WorkspaceLayout {
  return {
    navWidth: Math.min(NAV_MAX_WIDTH, Math.max(NAV_MIN_WIDTH, layout.navWidth)),
    listWidth: Math.min(LIST_MAX_WIDTH, Math.max(LIST_MIN_WIDTH, layout.listWidth)),
  };
}

export function clampLayout(layout: WorkspaceLayout, viewportWidth: number): WorkspaceLayout {
  let navWidth = Math.min(NAV_MAX_WIDTH, Math.max(NAV_MIN_WIDTH, layout.navWidth));
  let listWidth = Math.min(LIST_MAX_WIDTH, Math.max(LIST_MIN_WIDTH, layout.listWidth));
  const available = Math.max(
    NAV_MIN_WIDTH + LIST_MIN_WIDTH,
    viewportWidth - DETAIL_MIN_WIDTH - SEPARATORS_WIDTH,
  );
  if (navWidth + listWidth > available) listWidth = Math.max(LIST_MIN_WIDTH, available - navWidth);
  if (navWidth + listWidth > available) navWidth = Math.max(NAV_MIN_WIDTH, available - listWidth);
  return { navWidth, listWidth };
}
