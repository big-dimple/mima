import { useCallback, useEffect, useRef, useState } from 'react';
import { canEditItems, resolveEffectiveRole } from '@mima/domain';
import { useApp } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { writeGuideState } from '../utils/guide-storage.ts';
import styles from './OnboardingTour.module.css';

const FOCUSABLE_SELECTOR = 'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])';

interface TourStep {
  /** data-tour 锚点名：高亮界面上的真实控件。 */
  target: string;
  /** 主锚点不存在时的备用锚点（如非拥有者看不到成员管理按钮）。 */
  fallback?: string | readonly string[];
  title: string;
  body: string;
  /** 备用锚点生效时替换的文案。 */
  fallbackBody?: string;
  /** 备用锚点生效时替换的标题。 */
  fallbackTitle?: string;
  /** 进入该步骤前的准备动作（如自动选中第一个条目）。 */
  prepare?: (ctx: { selectFirstItem: () => boolean; selectWritableVault: () => boolean }) => void;
}

const STEPS: TourStep[] = [
  {
    target: 'vault-nav',
    fallback: 'open-vault-nav',
    title: '选择密码库',
    body: '左侧分为个人库和团队库。点击库名即可切换；铅笔用来改名，团队库旁还能查看操作记录和管理成员。',
    fallbackBody: '点这里打开密码库列表。个人库只有你自己能看；团队库由拥有者决定谁能访问。',
  },
  {
    target: 'nav-resizer',
    fallback: 'open-vault-nav',
    title: '调宽左栏',
    fallbackTitle: '打开密码库列表',
    body: '密码库名称显示不全时，抓住带竖点的分隔线向右拖，左栏可以拉得更宽；双击分隔线会恢复默认宽度。调整结果只保存在当前浏览器。',
    fallbackBody: '在平板或手机上点这里打开密码库列表，库名会自动换行显示，不需要手动调整宽度。',
  },
  {
    target: 'rename-vault',
    fallback: 'open-vault-nav',
    title: '修改库名',
    body: '点铅笔可以随时修改密码库名称。新名称会先在当前设备加密，再同步到服务器。',
    fallbackBody: '打开密码库列表后，点个人库或你拥有的团队库旁边的铅笔即可改名。',
  },
  {
    target: 'new-item',
    title: '新建条目',
    body: '选中一个你可编辑的密码库后，就能添加账号密码、API 凭证或安全备注。账号密码适合网站、服务器和数据库；填写网址后，浏览器扩展还能在对应网站帮你自动填充。',
    prepare: (ctx) => {
      ctx.selectWritableVault();
    },
  },
  {
    target: 'search',
    title: '搜索',
    body: '在这里输入标题、说明、凭证标识或关联信息，结果会在当前设备立即筛选，不会把搜索词发给服务器。按 / 键可随时回到搜索框。',
  },
  {
    target: 'secret-field',
    fallback: 'new-item',
    title: '查看与复制',
    body: '密码默认遮罩。点“查看”会临时显示；点“复制”不会把密码展示在页面上，并会在 30 秒后尽力清理剪贴板。',
    fallbackBody: '创建并选中第一条记录后，详情区会出现“查看”和“复制”：查看会自动恢复遮罩，复制后会在 30 秒后尽力清理剪贴板。',
    prepare: (ctx) => {
      ctx.selectFirstItem();
    },
  },
  {
    target: 'new-team',
    fallback: 'open-vault-nav',
    title: '创建团队库',
    body: '个人使用走通后，点“团队”右侧的加号，填写名称就能创建团队密码库，默认由你担任拥有者；不需要先配置企业恢复。',
    fallbackBody: '打开密码库列表后，点“团队”右侧的加号，填写名称即可创建团队密码库。',
  },
  {
    target: 'members',
    fallback: ['new-team', 'open-vault-nav'],
    title: '团队授权',
    body: '你是这个团队库的拥有者：点这里管理成员，决定谁能查看、谁能编辑，或者给合规同事一个“只能查记录、不能看密码”的审计角色。同事登录并设置主密码后，由你完成访问开通。',
    fallbackBody: '还没有团队库时先从这里创建；创建后点库名旁的成员按钮添加同事。如果搜不到或暂时不能选择，请让对方先登录一次并设置主密码。',
  },
  {
    target: 'pair-extension',
    fallback: 'more-tools',
    title: '配对浏览器扩展',
    body: '点这里生成一个 120 秒内有效的一次性配对码，输入到浏览器侧边栏扩展中。扩展优先匹配完整登录地址，同协议、域名和端口下也会给出同站点候选。',
    fallbackBody: '在窄屏上先打开“更多工具”，再选择“配对浏览器扩展”。扩展优先匹配完整登录地址，并拒绝协议、域名或端口不同的页面。',
  },
  {
    target: 'lock',
    title: '锁定与退出',
    body: '离开座位前点一下锁：当前页面会清除解锁信息、搜索内容和已经显示的密码，并尝试清理刚复制的内容。回来后输入主密码即可继续。右侧按钮用于退出登录。',
  },
];

/**
 * 互动引导：逐步高亮界面上的真实控件（data-tour 锚点）。
 * 遮罩不拦截布局（spotlight 用 box-shadow 挖洞）；无动画，兼容窄屏。
 * 完成状态只写非敏感 localStorage。
 */
export function OnboardingTour() {
  const { store } = useApp();
  const tourStep = useUi((s) => s.tourStep);
  const setTourStep = useUi((s) => s.setTourStep);
  const toast = useUi((s) => s.toast);
  const [rect, setRect] = useState<DOMRect | null>(null);
  const [usingFallback, setUsingFallback] = useState(false);
  const directionRef = useRef(1);
  const cardRef = useRef<HTMLDivElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);

  const selectFirstItem = useCallback((): boolean => {
    const ui = useUi.getState();
    if (ui.selectedItemId) return true;
    const items = Object.values(store.getState().items);
    if (items.length === 0) return false;
    const first = [...items].sort((a, b) => a.title.localeCompare(b.title, 'zh-CN'))[0]!;
    ui.selectItem(first.id);
    return true;
  }, [store]);

  const selectWritableVault = useCallback((): boolean => {
    const ui = useUi.getState();
    const state = store.getState();
    const selected = state.vaults[ui.selectedVaultId];
    if (selected && state.user) {
      const role = selected.kind === 'personal'
        ? 'owner'
        : resolveEffectiveRole(state.memberships[selected.id] ?? [], {
          userId: state.user.id,
          groups: state.user.groups,
        });
      if (canEditItems(role)) return true;
    }
    const personal = Object.values(state.vaults).find((vault) => vault.kind === 'personal');
    if (!personal) return false;
    ui.selectVault(personal.id);
    return true;
  }, [store]);

  const step = tourStep !== null ? STEPS[tourStep] : undefined;

  // 定位目标控件：准备动作 → 查找锚点（缺失用备用）→ 滚动进视野
  useEffect(() => {
    if (tourStep === null || !step) return;
    step.prepare?.({ selectFirstItem, selectWritableVault });
    let cancelled = false;
    const locate = () => {
      if (cancelled) return;
      let el = findVisibleTourTarget(step.target);
      let fallback = false;
      if (!el && step.fallback) {
        const fallbackTargets = Array.isArray(step.fallback) ? step.fallback : [step.fallback];
        for (const target of fallbackTargets) {
          el = findVisibleTourTarget(target);
          if (el) {
            fallback = true;
            break;
          }
        }
      }
      if (!el) {
        // 目标与备用都不存在：按当前方向跳过该步骤
        const next = tourStep + directionRef.current;
        if (next < 0 || next >= STEPS.length) {
          setTourStep(null);
        } else {
          setTourStep(next);
        }
        return;
      }
      el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      setUsingFallback(fallback);
      setRect(el.getBoundingClientRect());
    };
    // prepare 可能触发 React 重渲染（如选中条目后 SecretField 才出现），下一帧再定位
    const raf = requestAnimationFrame(() => setTimeout(locate, 50));
    const interval = setInterval(locate, 400);
    window.addEventListener('resize', locate);
    return () => {
      cancelled = true;
      cancelAnimationFrame(raf);
      clearInterval(interval);
      window.removeEventListener('resize', locate);
    };
  }, [tourStep, step, selectFirstItem, selectWritableVault, setTourStep]);

  // 焦点管理：打开时记住并聚焦卡片，关闭时归还焦点
  useEffect(() => {
    if (tourStep !== null) {
      previousFocusRef.current = document.activeElement as HTMLElement | null;
      const timer = setTimeout(() => {
        cardRef.current?.focus();
      }, 60);
      return () => clearTimeout(timer);
    }
    if (previousFocusRef.current && document.body.contains(previousFocusRef.current)) {
      previousFocusRef.current.focus();
      previousFocusRef.current = null;
    }
  }, [tourStep]);

  // Tab 焦点循环限制在引导卡片内
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'Tab' || !cardRef.current) return;
    const focusable = Array.from(cardRef.current.querySelectorAll(FOCUSABLE_SELECTOR)) as HTMLElement[];
    if (focusable.length === 0) return;
    const first = focusable[0]!;
    const last = focusable[focusable.length - 1]!;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  if (tourStep === null || !step || !rect) return null;
  const cardTitle = usingFallback && step.fallbackTitle ? step.fallbackTitle : step.title;

  const finish = (completed: boolean) => {
    setTourStep(null);
    setRect(null);
    if (completed) {
      writeGuideState({ tourCompleted: true, promptShown: true });
      toast('info', '入门引导完成！随时可从顶栏"新手指南"再次打开。');
    } else {
      writeGuideState({ promptShown: true });
    }
  };

  const go = (delta: number) => {
    directionRef.current = delta;
    const next = tourStep + delta;
    if (next >= STEPS.length) {
      finish(true);
      return;
    }
    if (next < 0) return;
    setRect(null);
    setTourStep(next);
  };

  // 提示卡位置：优先目标下方 → 上方 → （全高目标）右侧；始终夹取在视口内
  const pad = 6;
  const cardW = Math.min(340, window.innerWidth - 24);
  const estH = 220;
  const clampX = (x: number) => Math.max(12, Math.min(x, window.innerWidth - cardW - 12));
  const clampY = (y: number) => Math.max(12, Math.min(y, window.innerHeight - estH - 12));
  let cardTop: number;
  let cardLeft: number;
  if (rect.bottom + estH + 12 <= window.innerHeight) {
    cardTop = rect.bottom + 12;
    cardLeft = clampX(rect.left);
  } else if (rect.top - estH - 12 >= 0) {
    cardTop = rect.top - estH - 12;
    cardLeft = clampX(rect.left);
  } else {
    cardTop = clampY(rect.top + 40);
    cardLeft = rect.right + 12 + cardW <= window.innerWidth ? rect.right + 12 : clampX(rect.left);
  }

  return (
    <div
      className={styles.layer}
      role="dialog"
      aria-modal="true"
      aria-label={`引导：${cardTitle}`}
      onKeyDown={handleKeyDown}
    >
      <div
        className={styles.spotlight}
        style={{
          top: rect.top - pad,
          left: rect.left - pad,
          width: rect.width + pad * 2,
          height: rect.height + pad * 2,
        }}
      />
      <div
        ref={cardRef}
        className={styles.card}
        style={{ top: cardTop, left: cardLeft, width: cardW }}
        tabIndex={-1}
      >
        <div className={styles.cardHead}>
          <strong>{cardTitle}</strong>
          <span className={styles.progress}>{tourStep + 1} / {STEPS.length}</span>
        </div>
        <p className={styles.body}>{usingFallback && step.fallbackBody ? step.fallbackBody : step.body}</p>
        <div className={styles.cardActions}>
          <button className={styles.skip} onClick={() => finish(false)}>跳过引导</button>
          <span className={styles.spacer} />
          {tourStep > 0 && (
            <button className={styles.nav} onClick={() => go(-1)}>上一步</button>
          )}
          <button className={styles.primary} onClick={() => go(1)}>
            {tourStep === STEPS.length - 1 ? '完成' : '下一步'}
          </button>
        </div>
      </div>
    </div>
  );
}

function findVisibleTourTarget(name: string): Element | null {
  return Array.from(document.querySelectorAll(`[data-tour="${name}"]`)).find((element) => {
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return rect.width > 0 && rect.height > 0 && style.display !== 'none' && style.visibility !== 'hidden';
  }) ?? null;
}
