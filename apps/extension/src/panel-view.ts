import {
  CircleUserRound,
  ExternalLink,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldAlert,
  Star,
  StickyNote,
  Unplug,
  createElement as createIconElement,
  type IconNode,
} from 'lucide';
import { getItemPresentation, getVisibleItemAuxiliary } from '@mima/domain';
import { PanelActions } from './panel-actions.ts';
import { PanelModel } from './panel-model.ts';
import type { DecryptedExtensionItem, LocalDeviceRecord } from './protocol.ts';
import { extensionItemMatchScore } from './site-match.ts';

export class PanelView {
  constructor(
    private readonly root: HTMLElement,
    private readonly model: PanelModel,
    private readonly actions: PanelActions,
    private readonly retryStartup: () => Promise<void>,
  ) {}

  render(): void {
    this.root.replaceChildren();
    switch (this.model.state.phase) {
      case 'loading':
        this.renderLoading('正在加载扩展…');
        break;
      case 'pairing':
        this.renderPairing();
        break;
      case 'awaiting_approval':
        this.renderAwaitingApproval();
        break;
      case 'locked':
        this.renderLocked();
        break;
      case 'unlocking':
        this.renderLoading('正在本地解锁…');
        break;
      case 'ready':
        this.renderMain();
        break;
      case 'revoked':
        this.renderRevoked();
        break;
      case 'error':
        this.renderError();
        break;
    }
  }

  showStatus(text: string, isError = false): void {
    document.querySelector('.status')?.remove();
    const status = element('div', `status${isError ? ' error' : ''}`, text);
    status.setAttribute('role', isError ? 'alert' : 'status');
    status.setAttribute('aria-live', isError ? 'assertive' : 'polite');
    document.body.appendChild(status);
    setTimeout(() => status.remove(), 3_500);
  }

  private renderLoading(message: string): void {
    const state = element('div', 'panelState');
    state.setAttribute('role', 'status');
    state.setAttribute('aria-live', 'polite');
    state.appendChild(element('span', 'spinner'));
    state.appendChild(element('span', undefined, message));
    this.root.appendChild(state);
  }

  private renderError(): void {
    const state = element('div', 'panelState panelStateError');
    state.setAttribute('role', 'alert');
    state.appendChild(element('h1', 'panelStateTitle', '扩展暂时不可用'));
    state.appendChild(element('p', 'panelStateMessage', this.model.state.error ?? '初始化失败，请稍后重试。'));
    const retry = button('重试', 'btn btnPrimary');
    retry.addEventListener('click', () => {
      retry.disabled = true;
      void this.retryStartup();
    });
    state.appendChild(retry);
    this.root.appendChild(state);
  }

  private renderRevoked(): void {
    const state = element('div', 'panelState panelStateError');
    state.setAttribute('role', 'alert');
    state.appendChild(element('h1', 'panelStateTitle', '此设备已被撤销'));
    state.appendChild(element('p', 'panelStateMessage', '此浏览器保存的扩展授权和离线数据已清除。'));
    const restart = button('重新配对', 'btn btnPrimary');
    restart.addEventListener('click', () => {
      this.model.setPairing();
      this.render();
    });
    state.appendChild(restart);
    this.root.appendChild(state);
  }

  private renderPairing(): void {
    const wrap = element('form', 'pairing') as HTMLFormElement;
    wrap.appendChild(element('h1', undefined, 'Mima · 扩展配对'));
    wrap.appendChild(element('p', undefined, '在已解锁的工作台生成一次性配对码，并核对设备指纹。'));
    if (this.model.state.error) wrap.appendChild(alertBox(this.model.state.error));

    const code = labeledInput(wrap, '一次性配对码', '配对码', 'text');
    code.autocomplete = 'off';
    code.spellcheck = false;
    code.maxLength = 8;
    code.classList.add('codeInput');

    const deviceName = labeledInput(wrap, '设备名称', defaultDeviceName(), 'text');
    deviceName.value = defaultDeviceName();
    deviceName.autocomplete = 'off';
    deviceName.maxLength = 120;

    const existingDevice = this.model.state.device?.pairingOnly
      ? null
      : this.model.state.device;
    const factorLabel = extensionUnlockLabel(existingDevice);
    let factor: HTMLInputElement | null = null;
    if (existingDevice) {
      wrap.appendChild(element(
        'p',
        'fieldHint',
        '这是旧设备的兼容升级，只需输入一次当前主密码。完成后，工作台和扩展会一起解锁。',
      ));
      factor = labeledInput(wrap, factorLabel, '', 'password');
      factor.autocomplete = 'current-password';
    } else {
      wrap.appendChild(element(
        'p',
        'fieldHint',
        '无需在扩展重复输入主密码。批准设备后，已解锁的工作台会安全完成本机设置。',
      ));
    }

    const errorBox = element('div');
    wrap.appendChild(errorBox);
    const submit = button('开始配对', 'btn btnPrimary');
    wrap.appendChild(submit);

    code.addEventListener('input', () => {
      code.value = code.value.toUpperCase().replace(/[^A-Z2-9]/g, '').slice(0, 8);
    });
    wrap.addEventListener('submit', (event) => {
      event.preventDefault();
      errorBox.replaceChildren();
      errorBox.className = '';
      const message = validatePairingForm(
        code.value,
        deviceName.value,
        factor?.value ?? '',
        factorLabel,
        Boolean(existingDevice),
      );
      if (message) {
        showInlineError(errorBox, message);
        return;
      }
      submit.disabled = true;
      submit.textContent = '正在连接此扩展…';
      const unlockFactor = factor?.value || undefined;
      if (factor) factor.value = '';
      void this.actions.pair({
        code: code.value,
        unlockFactor,
        deviceName: deviceName.value.trim(),
        platform: extensionPlatform(),
      }).then(() => this.render()).catch((error) => {
        showInlineError(errorBox, errorMessage(error, '配对失败'));
        submit.disabled = false;
        submit.textContent = '开始配对';
      });
    });
    this.root.appendChild(wrap);
    code.focus();
  }

  private renderAwaitingApproval(): void {
    const pending = this.model.state.pendingEnrollment;
    if (!pending) {
      this.model.setPairing();
      this.render();
      return;
    }
    const wrap = element('div', 'pairing fingerprintPanel');
    wrap.appendChild(element('h1', undefined, '核对设备指纹'));
    wrap.appendChild(element('p', undefined, '确认工作台显示的指纹与下方完全一致。'));
    const fingerprint = element('code', 'fingerprint', pending.fingerprint);
    fingerprint.setAttribute('aria-label', `设备指纹 ${pending.fingerprint}`);
    wrap.appendChild(fingerprint);
    wrap.appendChild(element('p', 'expires', `本次申请 ${formatExpiry(pending.expiresAt)} 失效`));
    const factorLabel = extensionUnlockLabel(this.model.state.device);
    const factor = pending.sealedApproval && !this.model.state.device?.pairingOnly
      ? labeledInput(wrap, factorLabel, '', 'password')
      : null;
    if (factor) factor.autocomplete = 'current-password';
    const errorBox = element('div');
    wrap.appendChild(errorBox);
    const check = button(
      factor ? `用${factorLabel}完成配对` : '已确认，检查授权',
      'btn btnPrimary',
    );
    check.addEventListener('click', () => {
      check.disabled = true;
      check.textContent = '正在检查…';
      errorBox.replaceChildren();
      const unlockFactor = factor?.value;
      if (factor) factor.value = '';
      void this.actions.checkPairingApproval(unlockFactor).then((status) => {
        if (status === 'pending') {
          showInlineError(errorBox, '工作台尚未确认，请核对指纹后重试');
          check.disabled = false;
          check.textContent = '已确认，检查授权';
          return;
        }
        if (status === 'awaiting_unlock') {
          this.render();
          return;
        }
        this.render();
      }).catch((error) => {
        if (this.model.state.phase !== 'awaiting_approval') {
          this.render();
          return;
        }
        showInlineError(errorBox, errorMessage(error, '检查授权失败'));
        check.disabled = false;
        check.textContent = factor ? `用${factorLabel}完成配对` : '已确认，检查授权';
      });
    });
    wrap.appendChild(check);
    const cancel = button('取消本次配对', 'btn btnSecondary');
    cancel.type = 'button';
    cancel.addEventListener('click', () => {
      cancel.disabled = true;
      void this.actions.cancelPendingPairing().then(() => this.render());
    });
    wrap.appendChild(cancel);
    this.root.appendChild(wrap);
  }

  private renderLocked(): void {
    const session = this.model.state.session;
    const device = this.model.state.device;
    if (!device) {
      this.model.setPairing('扩展配对信息不完整，请重新配对');
      this.render();
      return;
    }
    this.root.appendChild(this.renderHeader(false));
    const wrap = element('form', 'unlockPanel') as HTMLFormElement;
    wrap.appendChild(element(
      'h1',
      'panelStateTitle',
      session ? '扩展已锁定' : device.webUnlock ? '恢复扩展连接' : '完成设备升级',
    ));
    wrap.appendChild(element(
      'p',
      'panelStateMessage',
      session ? `${device.name} · ${session.user.displayName}` : `${device.name} · 无需重新配对`,
    ));
    if (this.model.state.error) wrap.appendChild(alertBox(this.model.state.error));
    if (!session && device.webUnlock) {
      const resume = button('从已解锁工作台恢复', 'btn btnPrimary');
      resume.type = 'button';
      resume.addEventListener('click', () => {
        resume.disabled = true;
        resume.textContent = '正在确认…';
        void this.actions.tryTrustedUnlock({ force: true }).then(() => this.render()).catch(() => this.render());
      });
      wrap.appendChild(resume);
      wrap.appendChild(element(
        'p',
        'fieldHint',
        '保持同一账号工作台已解锁；系统会自动选择可响应的标签页。当前设备仍受信任，不需要重新配对。',
      ));
      this.root.appendChild(wrap);
      return;
    }
    if (device.webUnlock) {
      const retry = button('重试工作台联动', 'btn btnSecondary');
      retry.type = 'button';
      retry.addEventListener('click', () => {
        retry.disabled = true;
        retry.textContent = '正在确认…';
        void this.actions.tryTrustedUnlock({ force: true }).then(() => this.render()).catch(() => this.render());
      });
      wrap.appendChild(retry);
      wrap.appendChild(element('p', 'fieldHint', '工作台未打开或账号不一致时，可在这里输入同一主密码。'));
    }
    if (!session) {
      wrap.appendChild(element(
        'p',
        'fieldHint',
        '无需配对码。先打开并解锁工作台，再输入最后一次主密码，把旧设备升级为长期可信设备。',
      ));
    }
    const factor = labeledInput(wrap, extensionUnlockLabel(device), '', 'password');
    factor.autocomplete = 'current-password';
    const submit = button(session ? '用主密码解锁' : '完成设备升级', 'btn btnPrimary');
    wrap.appendChild(submit);
    wrap.addEventListener('submit', (event) => {
      event.preventDefault();
      if (!factor.value) return;
      submit.disabled = true;
      const unlockFactor = factor.value;
      factor.value = '';
      void this.actions.unlock(unlockFactor).then(() => this.render()).catch(() => {
        if (this.model.state.phase !== 'locked') {
          this.render();
          return;
        }
        submit.disabled = false;
        this.render();
      });
    });
    this.root.appendChild(wrap);
    factor.focus();
  }

  private renderMain(): void {
    const session = this.model.state.session;
    if (!session) {
      this.model.setLocked('与工作台的连接需要恢复，此扩展仍受信任，无需重新配对');
      this.render();
      return;
    }
    this.root.appendChild(this.renderHeader(true));
    if (this.model.state.offline) {
      const offline = element('div', 'offlineBanner', '暂时无法连接服务，当前显示此浏览器保存的数据');
      offline.setAttribute('role', 'status');
      this.root.appendChild(offline);
    }

    const originBar = element('div', 'originBar');
    const activeAddress = this.model.state.tabUrl ?? this.model.state.tabOrigin;
    if (activeAddress) {
      originBar.appendChild(element('span', 'originLabel', '当前页面'));
      const address = element('code', undefined, activeAddress);
      address.title = activeAddress;
      originBar.appendChild(address);
    } else {
      originBar.classList.add('originBarUnavailable');
      originBar.textContent = '未读取到当前网页，请切回网页后点刷新';
    }
    this.root.appendChild(originBar);

    const activeSite = {
      origin: this.model.state.tabOrigin,
      url: this.model.state.tabUrl,
    };
    const matched = this.model.state.items
      .filter((item) => item.kind === 'login' && item.secretState === 'present')
      .map((item) => ({ item, score: extensionItemMatchScore(item, activeSite) }))
      .filter(({ score }) => score > 0)
      .sort((left, right) => (
        right.score - left.score
        || Number(right.item.favorite) - Number(left.item.favorite)
        || left.item.title.localeCompare(right.item.title, 'zh-CN')
      ));
    const matchedIds = new Set(matched.map(({ item }) => item.id));
    this.root.appendChild(element('h2', 'section', `建议填充（${matched.length}）`));
    if (matched.length === 0) {
      this.root.appendChild(element('div', 'empty', '当前页面暂无可填充条目'));
    } else {
      const matchedList = element('div', 'results');
      matchedList.setAttribute('role', 'list');
      for (const { item, score } of matched) matchedList.appendChild(this.renderItem(item, score));
      this.root.appendChild(matchedList);
    }

    this.root.appendChild(element('h2', 'section', '全部条目'));
    const search = element('input', 'search') as HTMLInputElement;
    search.placeholder = '搜索已解锁条目…';
    search.setAttribute('aria-label', '搜索已解锁条目');
    search.value = this.model.state.search;
    this.root.appendChild(search);
    const results = element('div', 'results');
    results.setAttribute('role', 'list');
    this.root.appendChild(results);

    const updateResults = () => {
      results.replaceChildren();
      const query = this.model.state.search.trim().toLowerCase();
      const itemById = new Map(this.model.state.items.map((item) => [item.id, item]));
      const items = this.model.state.items
        .filter((item) => !matchedIds.has(item.id))
        .filter((item) => {
          if (!query) return true;
          const linkedLogin = item.linkedLoginItemId ? itemById.get(item.linkedLoginItemId) : undefined;
          return searchableItemText(item, linkedLogin).includes(query);
        })
        .slice(0, 50);
      if (items.length === 0) {
        results.appendChild(element('div', 'empty', '没有匹配的条目'));
      } else {
        for (const item of items) results.appendChild(this.renderItem(item, 0));
      }
    };
    search.addEventListener('input', () => {
      this.model.state.search = search.value;
      updateResults();
    });
    updateResults();
  }

  private renderHeader(unlocked: boolean): HTMLElement {
    const header = element('div', 'header');
    const identity = element('div', 'headerIdentity');
    identity.appendChild(element('span', 'brand', 'Mima'));
    if (this.model.state.session) {
      identity.appendChild(element('span', 'user', this.model.state.session.user.displayName));
    }
    header.appendChild(identity);

    const controls = element('div', 'headerActions');
    if (unlocked) {
      const refresh = iconButton('刷新', RefreshCw);
      refresh.addEventListener('click', () => {
        refresh.disabled = true;
        refresh.setAttribute('aria-busy', 'true');
        refresh.classList.add('isLoading');
        void this.actions.refreshData().then(() => this.render()).catch((error) => {
          if (this.model.state.phase !== 'ready') {
            this.render();
            return;
          }
          this.showStatus(errorMessage(error, '刷新失败'), true);
          refresh.disabled = false;
          refresh.removeAttribute('aria-busy');
          refresh.classList.remove('isLoading');
        });
      });
      controls.appendChild(refresh);
      const lock = iconButton('锁定', Lock);
      lock.addEventListener('click', () => {
        lock.disabled = true;
        void this.actions.lock().then(() => this.render());
      });
      controls.appendChild(lock);
    }
    const unpair = iconButton('解除配对', Unplug, true);
    unpair.addEventListener('click', () => {
      this.openUnpairConfirmation();
    });
    controls.appendChild(unpair);
    header.appendChild(controls);
    return header;
  }

  private renderItem(item: DecryptedExtensionItem, matchScore: 0 | 1 | 2): HTMLElement {
    const row = element('div', 'item');
    row.setAttribute('role', 'listitem');
    const presentation = getItemPresentation(item.kind);
    const auxiliary = getVisibleItemAuxiliary(item.kind, item.username);
    const body = element('div', 'itemBody');
    const title = element('div', 'itemTitle');
    title.appendChild(kindIcon(item.kind));
    title.appendChild(element('span', 'itemTitleText', item.title));
    title.appendChild(element('span', 'kindBadge', presentation.kindLabel));
    if (item.secretState === 'absent') title.appendChild(element('span', 'kindBadge', '仅入口'));
    if (item.favorite) title.appendChild(iconBadge('收藏', Star, 'favoriteBadge'));
    if (item.sensitivity === 'high') title.appendChild(iconBadge('高敏', ShieldAlert, 'highBadge'));
    body.appendChild(title);
    const itemSub = element('div', 'itemSub');
    if (matchScore > 0) {
      itemSub.appendChild(element(
        'span',
        `matchReason ${matchScore === 2 ? 'matchReasonExact' : 'matchReasonSite'}`,
        matchScore === 2 ? '精确地址' : '同站点',
      ));
    }
    itemSub.append([auxiliary, item.kind === 'login' ? item.loginUrl ?? item.origin : null]
      .filter(Boolean)
      .join(' · ') || presentation.kindLabel);
    body.appendChild(itemSub);
    row.appendChild(body);

    const itemActions = element('div', 'itemActions');

    if (item.secretState === 'absent') {
      if (item.kind === 'login' && (item.loginUrl || item.origin)) {
        const open = button('打开网址', 'btn btnPrimary');
        open.prepend(createIconElement(ExternalLink));
        open.addEventListener('click', () => {
          open.disabled = true;
          void this.actions.open(item).catch((error) => {
            this.handleActionFailure(error, '打开网址失败');
          }).finally(() => {
            if (this.model.state.phase === 'ready') open.disabled = false;
          });
        });
        itemActions.appendChild(open);
      }
      row.appendChild(itemActions);
      return row;
    }

    if (item.kind === 'login' && matchScore > 0) {
      const fill = button('填充', 'btn btnPrimary');
      fill.addEventListener('click', () => {
        fill.disabled = true;
        void this.actions.fill(item).then((message) => {
          if (message) this.showStatus(message, message !== '已填充登录表单');
        }).catch((error) => this.handleActionFailure(error, '填充失败')).finally(() => {
          if (this.model.state.phase === 'ready' && matchScore > 0) fill.disabled = false;
        });
      });
      itemActions.appendChild(fill);
    }

    const copy = button(presentation.copySecretLabel, 'btn btnSecondary');
    copy.title = presentation.copySecretLabel;
    copy.addEventListener('click', () => {
      copy.disabled = true;
      void this.actions.copy(item).then((message) => {
        if (message) this.showStatus(message);
      }).catch((error) => this.handleActionFailure(error, '复制失败')).finally(() => {
        if (this.model.state.phase === 'ready') copy.disabled = false;
      });
    });
    itemActions.appendChild(copy);
    row.appendChild(itemActions);
    return row;
  }

  private openUnpairConfirmation(): void {
    document.querySelector('.confirmLayer')?.remove();
    const layer = element('div', 'confirmLayer');
    layer.setAttribute('role', 'presentation');
    const dialog = element('div', 'confirmDialog');
    dialog.setAttribute('role', 'alertdialog');
    dialog.setAttribute('aria-modal', 'true');
    dialog.setAttribute('aria-labelledby', 'unpair-title');
    const title = element('h2', 'confirmTitle', '解除这台扩展的配对？');
    title.id = 'unpair-title';
    dialog.appendChild(title);
    dialog.appendChild(element('p', 'confirmBody', '此浏览器保存的扩展授权和离线数据会立即清除。重新使用前需要在工作台再次配对。'));
    const actions = element('div', 'confirmActions');
    const cancel = button('取消', 'btn btnSecondary');
    const confirm = button('解除配对', 'btn btnDanger');
    const close = () => layer.remove();
    cancel.addEventListener('click', close);
    confirm.addEventListener('click', () => {
      confirm.disabled = true;
      cancel.disabled = true;
      void this.actions.unpair().then(() => {
        close();
        this.render();
      });
    });
    layer.addEventListener('click', (event) => {
      if (event.target === layer) close();
    });
    layer.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') close();
    });
    actions.append(cancel, confirm);
    dialog.appendChild(actions);
    layer.appendChild(dialog);
    document.body.appendChild(layer);
    cancel.focus();
  }

  private handleActionFailure(error: unknown, fallback: string): void {
    if (this.model.state.phase !== 'ready') this.render();
    this.showStatus(errorMessage(error, fallback), true);
  }
}

function element(tag: string, className?: string, text?: string): HTMLElement {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function button(text: string, className: string): HTMLButtonElement {
  return element('button', className, text) as HTMLButtonElement;
}

function iconButton(label: string, icon: IconNode, danger = false): HTMLButtonElement {
  const control = button('', `iconBtn${danger ? ' iconBtnDanger' : ''}`);
  control.type = 'button';
  control.setAttribute('aria-label', label);
  control.title = label;
  const svg = createIconElement(icon);
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  control.appendChild(svg);
  return control;
}

function labeledInput(
  parent: HTMLElement,
  labelText: string,
  placeholder: string,
  type: 'password' | 'text',
): HTMLInputElement {
  const label = element('label', 'field');
  label.appendChild(element('span', 'fieldLabel', labelText));
  const input = element('input', 'fieldInput') as HTMLInputElement;
  input.type = type;
  input.placeholder = placeholder;
  input.setAttribute('aria-label', labelText);
  label.appendChild(input);
  parent.appendChild(label);
  return input;
}

function alertBox(message: string): HTMLElement {
  const box = element('div', 'error', message);
  box.setAttribute('role', 'alert');
  return box;
}

function showInlineError(target: HTMLElement, message: string): void {
  target.textContent = message;
  target.className = 'error';
  target.setAttribute('role', 'alert');
}

function searchableItemText(
  item: DecryptedExtensionItem,
  linkedLogin?: DecryptedExtensionItem,
): string {
  return [
    item.title,
    getVisibleItemAuxiliary(item.kind, item.username) ?? '',
    item.kind === 'login' ? item.loginUrl ?? item.origin ?? '' : '',
    item.description ?? '',
    linkedLogin?.kind === 'login' && linkedLogin.vaultId === item.vaultId ? linkedLogin.title : '',
    item.tags.join(' '),
  ]
    .join(' ')
    .toLowerCase();
}

function kindIcon(kind: DecryptedExtensionItem['kind']): SVGElement {
  const icon = kind === 'login' ? CircleUserRound : kind === 'api_token' ? KeyRound : StickyNote;
  const svg = createIconElement(icon);
  svg.classList.add('kindIcon');
  svg.setAttribute('aria-hidden', 'true');
  return svg;
}

function iconBadge(label: string, icon: IconNode, className: string): HTMLElement {
  const badge = element('span', className);
  badge.setAttribute('aria-label', label);
  badge.title = label;
  const svg = createIconElement(icon);
  svg.setAttribute('aria-hidden', 'true');
  badge.appendChild(svg);
  return badge;
}

function validatePairingForm(
  code: string,
  name: string,
  factor: string,
  factorLabel: string,
  factorRequired: boolean,
): string | null {
  if (code.length !== 8) return '请输入 8 位一次性配对码';
  if (!name.trim()) return '请输入设备名称';
  if (!factorRequired) return null;
  if (factor.length < 10) return `${factorLabel}至少需要 10 个字符`;
  return null;
}

function extensionUnlockLabel(device: LocalDeviceRecord | null): '主密码（本机解密）' | '旧版扩展解锁密码' {
  return !device || device.unlockFactorKind === 'web-main-password'
    ? '主密码（本机解密）'
    : '旧版扩展解锁密码';
}

function defaultDeviceName(): string {
  return `浏览器扩展 · ${navigator.platform || '当前设备'}`;
}

function extensionPlatform(): string {
  return `browser-extension/${navigator.platform || 'unknown'}`.slice(0, 80);
}

function formatExpiry(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? '即将'
    : date.toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' });
}

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}
