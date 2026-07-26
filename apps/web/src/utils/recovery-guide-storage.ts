const KEY = 'mima.recovery-guide.v1';

export interface RecoveryGuideState {
  promptShown: boolean;
  completed: boolean;
}

export function readRecoveryGuideState(): RecoveryGuideState {
  try {
    const parsed = JSON.parse(localStorage.getItem(KEY) ?? '{}') as Partial<RecoveryGuideState>;
    return {
      promptShown: parsed.promptShown === true,
      completed: parsed.completed === true,
    };
  } catch {
    return { promptShown: false, completed: false };
  }
}

export function writeRecoveryGuideState(patch: Partial<RecoveryGuideState>): void {
  try {
    localStorage.setItem(KEY, JSON.stringify({ ...readRecoveryGuideState(), ...patch }));
  } catch {
    // Private browsing may disable localStorage; the guide remains replayable.
  }
}
