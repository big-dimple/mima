/// <reference lib="webworker" />
import { E2eeKeyring } from '@mima/client-core';
import {
  isWebCryptoWorkerMethod,
  type WebCryptoWorkerRequest,
  type WebCryptoWorkerResponse,
} from './crypto-worker-protocol.ts';

const keyring = new E2eeKeyring();

self.onmessage = (event: MessageEvent<unknown>) => {
  const request = parseRequest(event.data);
  if (!request) return;
  void run(request).finally(() => {
    request.args.length = 0;
  });
};

async function run(request: WebCryptoWorkerRequest): Promise<void> {
  try {
    const method = (keyring as unknown as Record<string, (...args: unknown[]) => unknown>)[request.method];
    if (typeof method !== 'function') throw new Error('浏览器安全模块不支持这项操作');
    const result = await method.apply(keyring, request.args);
    post({ id: request.id, ok: true, result });
  } catch (error) {
    post({
      id: request.id,
      ok: false,
      error: {
        message: error instanceof Error ? error.message : '加密操作失败',
        code: typeof error === 'object' && error !== null && 'code' in error
          ? String((error as { code: unknown }).code)
          : undefined,
      },
    });
  }
}

function parseRequest(value: unknown): WebCryptoWorkerRequest | null {
  if (
    !value ||
    typeof value !== 'object' ||
    !('id' in value) ||
    !Number.isSafeInteger(value.id) ||
    !('method' in value) ||
    !isWebCryptoWorkerMethod(value.method) ||
    !('args' in value) ||
    !Array.isArray(value.args)
  ) return null;
  return { id: value.id as number, method: value.method, args: value.args };
}

function post(response: WebCryptoWorkerResponse): void {
  self.postMessage(response);
}

export {};
