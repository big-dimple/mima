import { useState } from 'react';
import { Compass, X } from 'lucide-react';
import { useUi } from '../state/ui-store.ts';
import { readGuideState, writeGuideState } from '../utils/guide-storage.ts';
import styles from './TourPrompt.module.css';

/**
 * 首次进入工作台时的引导询问：角落小卡片，不遮挡工作区。
 * 无论选择"开始"还是"暂不"，都记录 promptShown（非敏感 localStorage），
 * 之后不再自动弹出；随时可从 Header"新手指南"再进入。
 */
export function TourPrompt() {
  const startTour = useUi((s) => s.startTour);
  const tourStep = useUi((s) => s.tourStep);
  const [visible, setVisible] = useState(() => !readGuideState().promptShown);

  if (!visible || tourStep !== null) return null;

  const dismiss = () => {
    writeGuideState({ promptShown: true });
    setVisible(false);
  };

  const start = () => {
    writeGuideState({ promptShown: true });
    setVisible(false);
    startTour();
  };

  return (
    <aside className={styles.card} role="complementary" aria-label="新手引导邀请">
      <button className={styles.close} aria-label="关闭" onClick={dismiss}>
        <X size={14} />
      </button>
      <div className={styles.head}>
        <Compass size={16} aria-hidden />
        <strong>第一次使用Mima？</strong>
      </div>
      <p className={styles.body}>
        花 3 分钟认识一下界面上的关键按钮：在哪找密码、怎么安全地复制、团队怎么授权。
      </p>
      <div className={styles.actions}>
        <button className={styles.primary} onClick={start}>开始引导</button>
        <button className={styles.later} onClick={dismiss}>暂不需要</button>
      </div>
    </aside>
  );
}
