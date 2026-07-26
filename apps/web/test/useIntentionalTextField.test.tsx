import { fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';
import { useIntentionalTextField } from '../src/hooks/useIntentionalTextField.ts';

describe('useIntentionalTextField', () => {
  it('rejects input events that have no direct user gesture', () => {
    render(<Harness />);
    const input = screen.getByLabelText('受保护输入');

    fireEvent.input(input, {
      target: { value: 'programmatic-or-autofilled' },
      inputType: 'insertReplacementText',
    });

    expect(input).toHaveValue('');
    expect(screen.getByTestId('touched')).toHaveTextContent('false');
  });

  it('accepts real keyboard input from the initially read-only control', async () => {
    render(<Harness />);
    const input = screen.getByLabelText('受保护输入');

    expect(input).toHaveAttribute('readonly');
    await userEvent.type(input, 'keyboard-value');

    expect(input).toHaveValue('keyboard-value');
    expect(input).not.toHaveAttribute('readonly');
  });

  it('accepts explicit paste, drop, and IME composition', () => {
    let rendered = render(<Harness />);
    let input = screen.getByLabelText('受保护输入');
    fireEvent.paste(input, { clipboardData: { getData: () => 'pasted-value' } });
    expect(input).toHaveValue('pasted-value');

    rendered.unmount();
    rendered = render(<Harness />);
    input = screen.getByLabelText('受保护输入');
    fireEvent.drop(input, { dataTransfer: { getData: () => 'dropped-value' } });
    expect(input).toHaveValue('dropped-value');

    rendered.unmount();
    rendered = render(<Harness />);
    input = screen.getByLabelText('受保护输入');
    fireEvent.compositionStart(input);
    fireEvent.input(input, { target: { value: '输入法内容' }, inputType: 'insertCompositionText' });
    fireEvent.compositionEnd(input);
    expect(input).toHaveValue('输入法内容');
  });
});

function Harness() {
  const field = useIntentionalTextField('');
  return (
    <>
      <label htmlFor="protected-input">受保护输入</label>
      <input
        id="protected-input"
        value={field.value}
        readOnly={!field.activated}
        onChange={field.onChange}
        onKeyDown={field.onKeyDown}
        onKeyUp={field.onKeyUp}
        onBlur={field.onBlur}
        onPaste={field.onPaste}
        onCut={field.onCut}
        onDrop={field.onDrop}
        onCompositionStart={field.onCompositionStart}
        onCompositionEnd={field.onCompositionEnd}
      />
      <output data-testid="touched">{String(field.touched)}</output>
    </>
  );
}
