/**
 * 新手引导状态：只存"首次自动启动已消费/完整完成"两个布尔值到 localStorage，
 * 不含任何用户身份、条目或敏感内容信息（非敏感数据，刷新/换设备丢失也无妨）。
 */
const KEY = 'mima.guide.v1';

export interface GuideState {
  /** 首次进入工作台的自动引导已经消费。 */
  promptShown: boolean;
  /** 互动引导已完整走完。 */
  tourCompleted: boolean;
}

export function readGuideState(): GuideState {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return { promptShown: false, tourCompleted: false };
    const parsed = JSON.parse(raw) as Partial<GuideState>;
    return {
      promptShown: parsed.promptShown === true,
      tourCompleted: parsed.tourCompleted === true,
    };
  } catch {
    return { promptShown: false, tourCompleted: false };
  }
}

export function writeGuideState(patch: Partial<GuideState>): void {
  try {
    localStorage.setItem(KEY, JSON.stringify({ ...readGuideState(), ...patch }));
  } catch {
    /* 隐私模式等禁用 localStorage 时静默降级：每次都会再询问 */
  }
}

export function consumeAutomaticGuideStart(): boolean {
  if (readGuideState().promptShown) return false;
  writeGuideState({ promptShown: true });
  return true;
}
