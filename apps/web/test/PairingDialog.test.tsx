import * as Tooltip from '@radix-ui/react-tooltip';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PairingDialog } from '../src/components/PairingDialog.tsx';
import { Toaster } from '../src/components/Toaster.tsx';
import { AppContext, type AppServices } from '../src/state/app-context.ts';
import { useUi } from '../src/state/ui-store.ts';
import { clearSecretClipboard } from '../src/utils/clipboard.ts';

describe('PairingDialog', () => {
  const writeText = vi.fn().mockResolvedValue(undefined);

  beforeEach(() => {
    useUi.setState({ pairingOpen: true, toasts: [] });
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    });
  });

  afterEach(async () => {
    useUi.setState({ pairingOpen: false, toasts: [] });
    await clearSecretClipboard();
    writeText.mockClear();
  });

  it('shows the initial countdown immediately and copies the one-time code', async () => {
    const services = {
      api: {
        createPairingCode: vi.fn().mockResolvedValue({
          code: 'ABCDEFG2',
          expiresAt: new Date(Date.now() + 120_000).toISOString(),
        }),
      },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider>
          <PairingDialog />
          <Toaster />
        </Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(await screen.findByText('ABCDEFG2')).toBeVisible();
    expect(screen.getByRole('timer')).toHaveTextContent(/\d+s 内有效/);
    await userEvent.click(screen.getByRole('button', { name: '复制配对码' }));
    expect(writeText).toHaveBeenCalledWith('ABCDEFG2');
    expect(screen.getByText(/配对码已复制/)).toBeVisible();
  });

  it('tracks only the generated code and keeps a claimed enrollment after the code timer ends', async () => {
    const enrollment = {
      id: '10000000-0000-4000-8000-000000000001',
      fingerprint: '1111 2222 3333 4444 5555 6666 7777 8888',
      expiresAt: new Date(Date.now() + 300_000).toISOString(),
      status: 'pending',
    };
    const extensionPairingStatus = vi.fn().mockResolvedValue({
      status: 'claimed',
      enrollment,
    });
    const services = {
      api: {
        createPairingCode: vi.fn().mockResolvedValue({
          code: 'EXACT222',
          expiresAt: new Date(Date.now() - 1_000).toISOString(),
        }),
        extensionPairingStatus,
      },
      zeroKnowledge: { approveExtensionEnrollment: vi.fn() },
    } as unknown as AppServices;

    render(
      <AppContext.Provider value={services}>
        <Tooltip.Provider><PairingDialog /></Tooltip.Provider>
      </AppContext.Provider>,
    );

    expect(await screen.findByText(enrollment.fingerprint)).toBeVisible();
    expect(extensionPairingStatus).toHaveBeenCalledWith('EXACT222');
    expect(screen.getByRole('timer')).toHaveTextContent('配对码已领取');
  });
});
