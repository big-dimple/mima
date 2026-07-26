import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RecoveryAdminTour } from '../src/components/RecoveryAdminTour.tsx';

describe('RecoveryAdminTour', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: false }));
    vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue(rect());
    Object.defineProperty(Element.prototype, 'scrollIntoView', {
      configurable: true,
      value: vi.fn(),
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('highlights real recovery sections and only navigates the guide', async () => {
    const finish = vi.fn();
    document.body.innerHTML = [
      'recovery-boundary',
      'recovery-key-manager',
      'recovery-coverage',
      'recovery-approvals',
      'recovery-requests',
    ].map((target) => `<section data-recovery-tour="${target}">${target}</section>`).join('');

    render(<RecoveryAdminTour onFinish={finish} />);
    await act(async () => vi.advanceTimersByTime(100));
    const tour = screen.getByRole('dialog', { name: /先看结论：安全但不失控/ });
    expect(tour).toBeVisible();
    expect(tour.parentElement).toBe(document.body);
    expect(tour.querySelector('[data-recovery-tour-card]')).toBeVisible();
    expect(screen.getByLabelText('本步骤播放进度')).toBeVisible();

    fireEvent.click(screen.getByRole('button', { name: '下一步' }));
    await act(async () => vi.advanceTimersByTime(100));
    expect(screen.getByRole('dialog', { name: /先把人员和材料分开准备/ })).toBeVisible();
    expect(finish).not.toHaveBeenCalled();
  });

  it('pauses autoplay when reduced motion is requested', async () => {
    vi.stubGlobal('matchMedia', vi.fn().mockReturnValue({ matches: true }));
    document.body.innerHTML = '<section data-recovery-tour="recovery-boundary">boundary</section>';

    render(<RecoveryAdminTour onFinish={vi.fn()} />);
    await act(async () => vi.advanceTimersByTime(100));
    expect(screen.getByRole('button', { name: '继续播放' })).toBeVisible();
  });
});

function rect(): DOMRect {
  return {
    x: 20,
    y: 20,
    top: 20,
    right: 420,
    bottom: 220,
    left: 20,
    width: 400,
    height: 200,
    toJSON: () => ({}),
  };
}
