import { describe, expect, it, vi } from 'vitest';
import { PanelApi, PanelApiError } from '../src/panel-api.ts';
import { PanelModel } from '../src/panel-model.ts';
import { extSession } from './helpers.ts';
import { ITEM_METADATA_FORMAT_HEADER, ITEM_METADATA_FORMAT_VERSION } from '@mima/contracts';

describe('PanelApi', () => {
  it('pins an authenticated request to the supplied session snapshot', async () => {
    const model = new PanelModel();
    const pinned = { ...extSession(), token: 'pinned-token', generation: 1 };
    model.state.session = { ...extSession(), token: 'newer-token', generation: 2 };
    const fetcher = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ profile: {}, items: [] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const api = new PanelApi('https://mima.example.test', model, fetcher);

    await api.encryptedBootstrap(pinned);

    const init = fetcher.mock.calls[0]![1] as RequestInit;
    expect(new Headers(init.headers).get('authorization')).toBe('Bearer pinned-token');
    expect(new Headers(init.headers).get(ITEM_METADATA_FORMAT_HEADER))
      .toBe(String(ITEM_METADATA_FORMAT_VERSION));
    expect(model.state.session?.token).toBe('newer-token');
  });

  it('turns the extension upgrade gate into actionable guidance', async () => {
    const model = new PanelModel();
    model.state.session = extSession();
    const fetcher = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      message: '扩展版本较旧，请更新扩展后继续使用；当前设备授权仍然保留，无需重新配对',
    }), { status: 426, headers: { 'content-type': 'application/json' } }));
    const api = new PanelApi('https://mima.example.test', model, fetcher);

    await expect(api.encryptedBootstrap()).rejects.toMatchObject({
      status: 426,
      message: '扩展版本较旧，请更新扩展后继续使用；当前设备授权仍然保留，无需重新配对',
    });
  });

  it('uses only v2 ciphertext endpoints and never calls legacy reveal', async () => {
    const model = new PanelModel();
    const session = extSession();
    model.state.session = session;
    const fetcher = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ metadata: {}, secret: {}, keyWrap: {} }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const api = new PanelApi('https://mima.example.test', model, fetcher);

    await api.encryptedContent('item-1', {
      purpose: 'copy',
      secretVersion: 1,
      deviceId: 'device-1',
      intentSignature: 'signature',
    });

    const url = String(fetcher.mock.calls[0]![0]);
    expect(url).toBe('https://mima.example.test/api/v2/extension/items/item-1/content');
    expect(url).not.toContain('reveal');
  });

  it('reports the failed bearer generation without clearing a newer shared session', async () => {
    const model = new PanelModel();
    const session = extSession();
    model.state.session = session;
    const fetcher = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ message: 'expired' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const api = new PanelApi('https://mima.example.test', model, fetcher);

    const error = await api.encryptedBootstrap().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(PanelApiError);
    expect(error).toMatchObject({
      message: '扩展在线连接需要恢复',
      status: 401,
      sessionGeneration: 1,
    });
    expect(model.state.session).toEqual(session);
    expect(model.state.phase).toBe('loading');
  });
});
