/**
 * 在页面上下文中执行的一次性填充函数（通过 chrome.scripting.executeScript 注入）。
 * 参数即时传入、用后即弃；不安装持久内容脚本，不留全局变量。
 */
export function fillLoginForm(username: string | null, password: string): { ok: boolean; reason?: string } {
  const visible = (el: HTMLElement) => {
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && getComputedStyle(el).visibility !== 'hidden';
  };
  const setNativeValue = (input: HTMLInputElement, value: string) => {
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set;
    setter?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
  };

  const passwordFields = Array.from(
    document.querySelectorAll<HTMLInputElement>('input[type="password"]'),
  ).filter(visible);
  const passwordInput = passwordFields[0];
  if (!passwordInput) return { ok: false, reason: '页面上未找到密码输入框' };

  if (username) {
    const scope: ParentNode = passwordInput.form ?? document;
    const candidates = Array.from(
      scope.querySelectorAll<HTMLInputElement>(
        'input[type="text"], input[type="email"], input:not([type])',
      ),
    ).filter(visible);
    // 取密码框之前最近的一个可见文本输入
    const before = candidates.filter(
      (el) => el.compareDocumentPosition(passwordInput) & Node.DOCUMENT_POSITION_FOLLOWING,
    );
    const usernameInput = before.at(-1) ?? candidates[0];
    if (usernameInput) setNativeValue(usernameInput, username);
  }
  setNativeValue(passwordInput, password);
  return { ok: true };
}
