import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { PasswordGenerator } from '../src/components/PasswordGenerator.tsx';

describe('PasswordGenerator', () => {
  it('keeps the generated value in transient DOM text and passes it only on command', () => {
    const onUse = vi.fn();
    const view = render(<PasswordGenerator onUse={onUse} />);
    const preview = view.container.querySelector('#pg-preview');
    const generated = preview?.textContent ?? '';

    expect(generated.length).toBeGreaterThanOrEqual(8);
    expect(screen.getByRole('button', { name: '使用' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: '使用' }));
    expect(onUse).toHaveBeenCalledWith(generated);

    for (const label of ['A-Z', 'a-z', '0-9', '!@#']) {
      fireEvent.click(screen.getByLabelText(label));
    }
    expect(preview).toHaveTextContent('请至少选择一类字符');
    expect(screen.getByRole('button', { name: '使用' })).toBeDisabled();

    view.unmount();
    expect(preview).toHaveTextContent('');
  });
});
