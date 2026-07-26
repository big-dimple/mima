import { useSyncExternalStore } from 'react';

/**
 * 原生 HTML5 拖拽的“环境启用”判定：仅当视口同时显示左右栏（桌面 ≥1120px）
 * 且指针为细指针（鼠标/触控板）时启用。平板、手机和粗指针一律用“移动到目录”弹窗。
 * 通过 matchMedia 订阅，视口或输入方式变化时组件即时重算。
 */
const POINTER_AND_LAYOUT_QUERY = '(min-width: 1120px) and (pointer: fine)';

function subscribe(callback: () => void): () => void {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return () => undefined;
  const media = window.matchMedia(POINTER_AND_LAYOUT_QUERY);
  media.addEventListener('change', callback);
  return () => media.removeEventListener('change', callback);
}

function getSnapshot(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false;
  return window.matchMedia(POINTER_AND_LAYOUT_QUERY).matches;
}

export function useDragEnvironment(): boolean {
  return useSyncExternalStore(subscribe, getSnapshot, () => false);
}
