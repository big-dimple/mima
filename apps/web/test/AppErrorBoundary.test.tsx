import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { AppErrorBoundary } from '../src/components/AppErrorBoundary.tsx';

function Broken(): never {
  throw new Error('render detail');
}

describe('AppErrorBoundary', () => {
  afterEach(() => vi.restoreAllMocks());

  it('replaces a failed tree with a safe reload action', () => {
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    render(
      <AppErrorBoundary>
        <Broken />
      </AppErrorBoundary>,
    );

    expect(screen.getByRole('alert')).toHaveTextContent('界面运行异常');
    expect(screen.getByRole('button', { name: '重试' })).toBeVisible();
  });
});
