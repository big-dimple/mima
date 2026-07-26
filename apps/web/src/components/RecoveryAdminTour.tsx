import { useEffect, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { Pause, Play, SkipForward } from 'lucide-react';
import styles from './RecoveryAdminTour.module.css';

const STEP_DURATION_MS = 7_000;
const TICK_MS = 100;

interface RecoveryTourStep {
  target: string;
  fallback?: string;
  title: string;
  body: string;
}

const STEPS: readonly RecoveryTourStep[] = [
  {
    target: 'recovery-overview',
    fallback: 'recovery-boundary',
    title: '先看结论：安全但不失控',
    body: '任何一个人都不能单独恢复。它恢复的是已纳入保护的密码库访问能力，不会找回旧主密码，也不能把个人库转交给别人。',
  },
  {
    target: 'recovery-key-manager',
    title: '先把人员和材料分开准备',
    body: '三位管理员负责平台确认，三份恢复材料分别离线保管。任何一名管理员或任何一份材料都无法单独完成恢复。',
  },
  {
    target: 'recovery-coverage',
    fallback: 'recovery-key-manager',
    title: '只保护明确纳入的密码库',
    body: '密码库所有者逐库添加恢复保护。没有纳入保护的库不会被恢复；个人库即使纳入，也只能恢复给原所有者本人。',
  },
  {
    target: 'recovery-approvals',
    fallback: 'recovery-key-manager',
    title: '真正恢复时仍要多人共同完成',
    body: '每次恢复都需要两位不同管理员确认；之后还要由两名材料保管人在隔离设备操作。审批不能代替离线材料。',
  },
  {
    target: 'recovery-requests',
    title: '最后由接收设备验证结果',
    body: '离线处理完成后，只有申请中指定的用户和设备可以导入结果。验证不通过就不会生效，整个过程会留下审计记录。',
  },
];

export function RecoveryAdminTour({
  onFinish,
}: {
  onFinish: (completed: boolean) => void;
}) {
  const reducedMotion = useRef(window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const [stepIndex, setStepIndex] = useState(0);
  const [playing, setPlaying] = useState(!reducedMotion.current);
  const [elapsed, setElapsed] = useState(0);
  const [rect, setRect] = useState<DOMRect | null>(null);
  const cardRef = useRef<HTMLDivElement>(null);

  const step = STEPS[stepIndex]!;

  useEffect(() => {
    const locate = () => {
      const target = findVisibleTarget(step.target) ?? (step.fallback ? findVisibleTarget(step.fallback) : null);
      if (!target) {
        if (stepIndex < STEPS.length - 1) setStepIndex((current) => current + 1);
        else onFinish(true);
        return;
      }
      target.scrollIntoView({ block: 'center', inline: 'nearest' });
      setRect(target.getBoundingClientRect());
    };
    const timer = window.setTimeout(locate, 80);
    window.addEventListener('resize', locate);
    window.addEventListener('scroll', locate, true);
    return () => {
      window.clearTimeout(timer);
      window.removeEventListener('resize', locate);
      window.removeEventListener('scroll', locate, true);
    };
  }, [step, stepIndex, onFinish]);

  useEffect(() => {
    setElapsed(0);
    cardRef.current?.focus();
  }, [stepIndex]);

  useEffect(() => {
    if (!playing) return;
    const interval = window.setInterval(() => {
      setElapsed((current) => Math.min(STEP_DURATION_MS, current + TICK_MS));
    }, TICK_MS);
    return () => window.clearInterval(interval);
  }, [playing, stepIndex]);

  useEffect(() => {
    if (elapsed < STEP_DURATION_MS) return;
    go(1);
  }, [elapsed]);

  useEffect(() => {
    const onVisibility = () => {
      if (document.hidden) setPlaying(false);
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);

  const go = (delta: number) => {
    const next = stepIndex + delta;
    if (next >= STEPS.length) {
      onFinish(true);
      return;
    }
    if (next < 0) return;
    setRect(null);
    setStepIndex(next);
  };

  if (!rect) return null;
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  const cardWidth = Math.min(380, viewportWidth - 24);
  const estimatedHeight = Math.min(280, viewportHeight - 24);
  const narrow = viewportWidth <= 720;
  const left = narrow ? 12 : clamp(rect.left, 12, viewportWidth - cardWidth - 12);
  const top = narrow
    ? undefined
    : rect.bottom + estimatedHeight + 12 <= viewportHeight
      ? rect.bottom + 12
      : clamp(rect.top - estimatedHeight - 12, 12, viewportHeight - estimatedHeight - 12);
  const spotlightLeft = clamp(rect.left - 6, 6, viewportWidth - 6);
  const spotlightTop = clamp(rect.top - 6, 6, viewportHeight - 6);
  const spotlightRight = clamp(rect.right + 6, spotlightLeft + 1, viewportWidth - 6);
  const spotlightBottom = clamp(rect.bottom + 6, spotlightTop + 1, viewportHeight - 6);

  return (
    <Dialog.Root open onOpenChange={(open) => {
      if (!open) onFinish(false);
    }}>
      <Dialog.Portal>
        <Dialog.Content
          asChild
          onOpenAutoFocus={(event) => {
            event.preventDefault();
            cardRef.current?.focus();
          }}
        >
          <div className={styles.layer}>
            <Dialog.Title className={styles.srOnly}>企业恢复管理者入门：{step.title}</Dialog.Title>
            <div
              className={styles.spotlight}
              style={{
                top: spotlightTop,
                left: spotlightLeft,
                width: spotlightRight - spotlightLeft,
                height: spotlightBottom - spotlightTop,
              }}
            />
            <div
              ref={cardRef}
              className={styles.card}
              data-recovery-tour-card
              style={narrow
                ? { bottom: 12, left, width: cardWidth }
                : { top, left, width: cardWidth }}
              tabIndex={-1}
              onPointerEnter={() => setPlaying(false)}
              onFocusCapture={(event) => {
                if (event.target !== event.currentTarget) setPlaying(false);
              }}
            >
              <div className={styles.head}>
                <strong>{step.title}</strong>
                <span className={styles.step}>{stepIndex + 1} / {STEPS.length}</span>
              </div>
              <Dialog.Description asChild><p className={styles.body}>{step.body}</p></Dialog.Description>
              <div className={styles.timeline} aria-label="本步骤播放进度">
                <span style={{ width: `${Math.min(100, elapsed / STEP_DURATION_MS * 100)}%` }} />
              </div>
              <div className={styles.actions}>
                <button className={styles.secondary} type="button" onClick={() => onFinish(false)}>
                  <SkipForward size={15} aria-hidden />跳过
                </button>
                <button className={styles.play} type="button" onClick={() => setPlaying((current) => !current)}>
                  {playing ? <Pause size={15} aria-hidden /> : <Play size={15} aria-hidden />}
                  {playing ? '暂停' : '继续播放'}
                </button>
                <span className={styles.spacer} />
                {stepIndex > 0 && <button className={styles.secondary} type="button" onClick={() => go(-1)}>上一步</button>}
                <button className={styles.primary} type="button" onClick={() => go(1)}>
                  {stepIndex === STEPS.length - 1 ? '完成' : '下一步'}
                </button>
              </div>
            </div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function findVisibleTarget(name: string): Element | null {
  return Array.from(document.querySelectorAll(`[data-recovery-tour="${name}"]`)).find((element) => {
    const rect = element.getBoundingClientRect();
    const style = window.getComputedStyle(element);
    return rect.width > 0 && rect.height > 0 && style.visibility !== 'hidden' && style.display !== 'none';
  }) ?? null;
}

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(value, max));
}
