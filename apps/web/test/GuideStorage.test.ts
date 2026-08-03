import { beforeEach, describe, expect, it } from 'vitest';
import {
  consumeAutomaticGuideStart,
  readGuideState,
} from '../src/utils/guide-storage.ts';

describe('automatic onboarding guide state', () => {
  beforeEach(() => localStorage.clear());

  it('consumes the automatic start before opening the tour', () => {
    expect(consumeAutomaticGuideStart()).toBe(true);
    expect(readGuideState()).toEqual({ promptShown: true, tourCompleted: false });
    expect(consumeAutomaticGuideStart()).toBe(false);
  });

  it('preserves existing completed and skipped users', () => {
    localStorage.setItem('mima.guide.v1', JSON.stringify({
      promptShown: true,
      tourCompleted: false,
    }));
    expect(consumeAutomaticGuideStart()).toBe(false);
  });

  it('treats damaged state as a first visit', () => {
    localStorage.setItem('mima.guide.v1', '{broken');
    expect(consumeAutomaticGuideStart()).toBe(true);
    expect(readGuideState()).toEqual({ promptShown: true, tourCompleted: false });
  });
});
