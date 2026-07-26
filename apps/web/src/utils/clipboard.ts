import { CLIPBOARD_CLEAR_MS } from '@mima/contracts';

let clearTimer: ReturnType<typeof setTimeout> | null = null;
let pendingSecret = false;

/**
 * 复制文本并在 30 秒后尽力清理剪贴板。
 * 浏览器无法可靠读取剪贴板确认归属，清理为 best-effort：
 * 仅当页面仍持有焦点时用空占位覆盖。
 * 锁定 / 退出 / 权限撤销时调用 clearSecretClipboard() 立即清理。
 */
export async function copyWithTimedClear(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
  pendingSecret = true;
  if (clearTimer) clearTimeout(clearTimer);
  clearTimer = setTimeout(() => void clearSecretClipboard(), CLIPBOARD_CLEAR_MS);
}

/** 立即清理剪贴板中我们写入的敏感内容（best-effort，不抛错）。 */
export async function clearSecretClipboard(): Promise<void> {
  if (!pendingSecret) return;
  pendingSecret = false;
  if (clearTimer) {
    clearTimeout(clearTimer);
    clearTimer = null;
  }
  try {
    if (document.hasFocus()) {
      await navigator.clipboard.writeText('');
    }
  } catch {
    /* 无焦点或权限不足时静默失败（见 docs/security-model.md 残余风险） */
  }
}
