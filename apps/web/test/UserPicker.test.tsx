import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { UserPicker } from '../src/components/UserPicker.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';

describe('UserPicker', () => {
  it('shows a preselected owner without requiring the user to open the search list', async () => {
    const searchUsers = vi.fn().mockResolvedValue({
      syncedAt: '2026-07-18T00:00:00.000Z',
      users: [{ id: 'u-bob', username: 'bob', displayName: 'Bob Li' }],
    });
    const services = { api: { searchUsers } } as unknown as AppServices;
    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <UserPicker value="u-bob" onChange={vi.fn()} label="初始拥有者" />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    const input = screen.getByRole('combobox', { name: '初始拥有者' });
    await waitFor(() => expect(input).toHaveValue('Bob Li (bob)'));
    expect(searchUsers).toHaveBeenCalledWith('', ['u-bob'], 1);
  });

  it('searches the server and selects a user without a full directory dropdown', async () => {
    const onChange = vi.fn();
    const searchUsers = vi.fn().mockResolvedValue({
      syncedAt: '2026-07-18T00:00:00.000Z',
      users: [{ id: 'u-200', username: 'alice', displayName: 'Alice' }],
    });
    const services = { api: { searchUsers } } as unknown as AppServices;
    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <UserPicker value="" onChange={onChange} label="初始拥有者" />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    const input = screen.getByRole('combobox', { name: '初始拥有者' });
    await userEvent.type(input, 'wang');
    const option = await screen.findByRole('option', { name: /Alice/ });
    expect(input).toHaveAttribute('aria-controls', option.parentElement?.id);
    expect(input).toHaveAttribute('aria-activedescendant', option.id);
    await userEvent.click(option);
    expect(searchUsers).toHaveBeenCalledWith('wang', []);
    expect(onChange).toHaveBeenCalledWith(
      'u-200',
      expect.objectContaining({ username: 'alice' }),
    );
  });
});
