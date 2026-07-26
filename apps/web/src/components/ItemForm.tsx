import { useMemo, useRef, useState } from 'react';
import { AlertTriangle, Save } from 'lucide-react';
import type { DecryptedItemMeta, DecryptedItemMetaPatch } from '@mima/client-core';
import type { ItemKind } from '@mima/contracts';
import {
  getItemPresentation,
  folderContainsPath,
  ITEM_DESCRIPTION_MAX_LENGTH,
  LOGIN_URL_MAX_LENGTH,
  materializeVaultDirectories,
  normalizeFolderPath,
  normalizeLoginUrl,
  normalizeOrigin,
} from '@mima/domain';
import { useIntentionalTextField } from '../hooks/useIntentionalTextField.ts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi, type NewItemPreset } from '../state/ui-store.ts';
import { ActionButton } from './ActionButton.tsx';
import { PasswordGenerator } from './PasswordGenerator.tsx';
import { SegmentedControl } from './SegmentedControl.tsx';
import styles from './ItemForm.module.css';

const KIND_OPTIONS: { value: ItemKind; label: string }[] = [
  { value: 'login', label: getItemPresentation('login').kindLabel },
  { value: 'api_token', label: getItemPresentation('api_token').kindLabel },
  { value: 'secure_note', label: getItemPresentation('secure_note').kindLabel },
];

const CONCURRENT_EDIT_MESSAGE = '这条记录刚刚有了新修改。系统已暂停保存，避免覆盖他人的内容。你的输入仍保留在本页；请先复制需要保留的部分，再取消编辑并查看最新内容';

export function ItemForm({
  mode,
  item,
  preset,
  onClose,
}: {
  mode: 'new' | 'edit';
  item?: DecryptedItemMeta;
  preset?: NewItemPreset | null;
  onClose: () => void;
}) {
  const { actions, store } = useApp();
  const ui = useUi();
  const connection = useMeta((state) => state.connection);
  const items = useMeta((state) => state.items);
  const conflicts = useMeta((state) => state.conflicts);
  const vaultDirectories = useMeta((state) => state.vaultDirectories);
  const toast = useUi((state) => state.toast);
  const initialItemRef = useRef(item);
  const initialItem = initialItemRef.current;

  const targetVaultId = initialItem?.vaultId ?? preset?.vaultId ?? ui.selectedVaultId;
  const [kind, setKind] = useState<ItemKind>(initialItem?.kind ?? preset?.kind ?? 'login');
  const [kindTouched, setKindTouched] = useState(false);
  const [baseVersion] = useState<number | undefined>(initialItem?.version);
  const title = useIntentionalTextField(initialItem?.title ?? '');
  const username = useIntentionalTextField(initialItem?.username ?? '');
  const loginUrl = useIntentionalTextField(initialItem?.loginUrl ?? initialItem?.origin ?? '');
  const description = useIntentionalTextField(initialItem?.description ?? '');
  const tags = useIntentionalTextField(initialItem?.tags.join(', ') ?? '');
  const secret = useIntentionalTextField('');
  const [folderPath, setFolderPath] = useState(
    initialItem?.folderPath ?? (
      mode === 'new' && targetVaultId === ui.selectedVaultId ? ui.selectedFolderPath ?? '' : ''
    ),
  );
  const [folderTouched, setFolderTouched] = useState(false);
  const [linkedLoginItemId, setLinkedLoginItemId] = useState(
    initialItem?.linkedLoginItemId ?? preset?.linkedLoginItemId ?? '',
  );
  const [linkedLoginTouched, setLinkedLoginTouched] = useState(false);
  const [highSensitivity, setHighSensitivity] = useState(initialItem?.sensitivity === 'high');
  const [sensitivityTouched, setSensitivityTouched] = useState(false);
  const [favorite, setFavorite] = useState(initialItem?.favorite ?? false);
  const [favoriteTouched, setFavoriteTouched] = useState(false);
  const [replaceSecret, setReplaceSecret] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submittingRef = useRef(false);

  const offline = connection !== 'online';
  const isNote = kind === 'secure_note';
  const presentation = getItemPresentation(kind);
  const secretEditorVisible = mode === 'new' || replaceSecret;
  const liveItem = initialItem ? items[initialItem.id] : undefined;
  const formStale = mode === 'edit' && Boolean(initialItem) && (
    !liveItem || liveItem.version !== baseVersion
  );
  const currentConflict = initialItem ? conflicts[initialItem.id] : undefined;
  const formConflicted = mode === 'edit' && Boolean(currentConflict);
  const formBlocked = formStale || formConflicted;
  const folderOptions = useMemo(() => materializeVaultDirectories(
    vaultDirectories[targetVaultId] ?? [],
    Object.values(items)
      .filter((candidate) => candidate.vaultId === targetVaultId)
      .map((candidate) => candidate.folderPath),
  ).map((entry) => entry.path), [items, targetVaultId, vaultDirectories]);
  const loginOptions = useMemo(() => Object.values(items)
    .filter((candidate) => (
      candidate.kind === 'login' &&
      candidate.vaultId === targetVaultId &&
      candidate.id !== initialItem?.id
    ))
    .sort((left, right) => left.title.localeCompare(right.title, 'zh-CN')), [initialItem?.id, items, targetVaultId]);

  const normalizedTitle = title.value.trim();
  const normalizedUsername = kind === 'secure_note' ? null : username.value.trim() || null;
  const normalizedLoginUrl = kind === 'login' && loginUrl.value.trim()
    ? normalizeLoginUrl(loginUrl.value.trim())
    : null;
  const normalizedOrigin = normalizedLoginUrl ? normalizeOrigin(normalizedLoginUrl) : null;
  const normalizedFolderPath = normalizeFolderPath(folderPath);
  const normalizedDescription = kind === 'secure_note' ? null : description.value.trim() || null;
  const normalizedLinkedLoginItemId = kind === 'api_token' ? linkedLoginItemId || null : null;
  const normalizedTags = parseTags(tags.value);

  const buildEditPatch = (): DecryptedItemMetaPatch => {
    if (!initialItem) return {};
    const patch: DecryptedItemMetaPatch = {};
    if (title.touched && normalizedTitle !== initialItem.title) patch.title = normalizedTitle;
    if (kind !== 'secure_note' && username.touched && normalizedUsername !== initialItem.username) {
      patch.username = normalizedUsername;
    }
    if (kind === 'login' && loginUrl.touched) {
      const baselineLoginUrl = initialItem.loginUrl ?? initialItem.origin;
      const normalizedBaselineLoginUrl = baselineLoginUrl ? normalizeLoginUrl(baselineLoginUrl) : null;
      if (normalizedOrigin !== initialItem.origin) patch.origin = normalizedOrigin;
      if (normalizedLoginUrl !== normalizedBaselineLoginUrl) patch.loginUrl = normalizedLoginUrl;
    }
    if (folderTouched && normalizedFolderPath !== (initialItem.folderPath ?? null)) {
      patch.folderPath = normalizedFolderPath;
    }
    if (
      kind !== 'secure_note' &&
      description.touched &&
      normalizedDescription !== (initialItem.description ?? null)
    ) {
      patch.description = normalizedDescription;
    }
    if (
      kind === 'api_token' &&
      linkedLoginTouched &&
      normalizedLinkedLoginItemId !== (initialItem.linkedLoginItemId ?? null)
    ) {
      patch.linkedLoginItemId = normalizedLinkedLoginItemId;
    }
    if (tags.touched && !sameStrings(normalizedTags, initialItem.tags)) patch.tags = normalizedTags;
    if (favoriteTouched && favorite !== initialItem.favorite) patch.favorite = favorite;
    if (sensitivityTouched && highSensitivity !== (initialItem.sensitivity === 'high')) {
      patch.sensitivity = highSensitivity ? 'high' : 'medium';
    }
    return patch;
  };

  const editPatch = mode === 'edit' ? buildEditPatch() : {};
  const changesSecret = secret.touched && secret.value.length > 0;
  const newDraftTouched = kindTouched
    || title.touched
    || username.touched
    || loginUrl.touched
    || folderTouched
    || description.touched
    || linkedLoginTouched
    || tags.touched
    || sensitivityTouched
    || favoriteTouched
    || secret.touched;
  const hasChanges = mode === 'new'
    ? newDraftTouched
    : changesSecret || Object.keys(editPatch).length > 0;

  const validate = (): string | null => {
    if (!normalizedTitle) return '标题不能为空';
    if ((mode === 'new' || folderTouched) && folderPath.trim() && normalizedFolderPath === null) {
      return '目录格式不正确，请使用 / 分层，最多 5 级且每级不超过 40 个字符';
    }
    if ((mode === 'new' || loginUrl.touched) && kind === 'login' && loginUrl.value.trim() && !normalizedLoginUrl) {
      return '网址格式不正确，例如 https://portal.example.test';
    }
    if ((mode === 'new' || description.touched) && description.value.length > ITEM_DESCRIPTION_MAX_LENGTH) {
      return '说明不能超过 1000 个字符';
    }
    if ((mode === 'new' || linkedLoginTouched) && kind === 'api_token' && linkedLoginItemId) {
      const linkedLogin = items[linkedLoginItemId];
      if (
        !linkedLogin ||
        linkedLogin.kind !== 'login' ||
        linkedLogin.vaultId !== targetVaultId ||
        linkedLogin.id === initialItem?.id
      ) return '关联账号密码已经不可用，请重新选择';
    }
    if (mode === 'new' && kind !== 'login' && (!secret.touched || !secret.value)) {
      return `${presentation.secretLabel}不能为空`;
    }
    return null;
  };

  const keepSavedItemVisible = (itemId: string, savedFolderPath: string | null) => {
    const currentFolder = ui.selectedFolderPath;
    const visible = currentFolder === null ||
      (currentFolder === '' ? savedFolderPath === null : folderContainsPath(currentFolder, savedFolderPath));
    if (!visible) ui.selectFolder(savedFolderPath ?? '');
    ui.selectItem(itemId);
  };

  const handleKindChange = (nextKind: ItemKind) => {
    if (nextKind === kind) return;
    setKind(nextKind);
    setKindTouched(true);
    username.reset();
    loginUrl.reset();
    description.reset();
    secret.reset();
    setLinkedLoginItemId('');
    setLinkedLoginTouched(false);
  };

  const handleReplaceSecret = (enabled: boolean) => {
    setReplaceSecret(enabled);
    if (!enabled) secret.reset();
  };

  const assertNoConflict = () => {
    if (initialItem && store.getState().conflicts[initialItem.id]) {
      throw new Error(CONCURRENT_EDIT_MESSAGE);
    }
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (submittingRef.current) return;
    if (formBlocked) {
      setError(null);
      return;
    }
    const validationError = validate();
    if (validationError) {
      setError(validationError);
      return;
    }
    if (!hasChanges) return;

    submittingRef.current = true;
    setError(null);
    setBusy(true);
    try {
      if (mode === 'new') {
        if (targetVaultId === 'all' || targetVaultId === 'favorites') {
          throw new Error('请先选择一个可编辑的密码库');
        }
        const id = await actions.createItem(targetVaultId, {
          kind,
          title: normalizedTitle,
          username: normalizedUsername,
          origin: normalizedOrigin,
          loginUrl: normalizedLoginUrl,
          folderPath: normalizedFolderPath,
          description: normalizedDescription,
          linkedLoginItemId: normalizedLinkedLoginItemId,
          tags: normalizedTags,
          favorite,
          sensitivity: highSensitivity ? 'high' : 'medium',
          secretValue: kind === 'login' && (!secret.touched || secret.value.length === 0)
            ? null
            : secret.value,
        });
        secret.reset();
        keepSavedItemVisible(id, normalizedFolderPath);
        onClose();
        toast('info', '条目已创建');
        return;
      }

      const itemId = initialItem!.id;
      let expectedVersion = baseVersion!;
      if (changesSecret) {
        await actions.rotateSecret(itemId, secret.value, expectedVersion);
        assertNoConflict();
        secret.reset();
        expectedVersion += 1;
      }
      if (Object.keys(editPatch).length > 0) {
        await actions.updateItemMeta(itemId, editPatch, expectedVersion);
        assertNoConflict();
      }
      keepSavedItemVisible(itemId, normalizedFolderPath);
      onClose();
      toast('info', offline ? '修改已在本地加密，将在恢复网络后同步' : '已保存');
    } catch (caught) {
      const currentItem = initialItem ? store.getState().items[initialItem.id] : undefined;
      const concurrentNow = Boolean(initialItem) && (
        !currentItem ||
        currentItem.version !== baseVersion ||
        Boolean(store.getState().conflicts[initialItem!.id])
      );
      setError(concurrentNow ? null : caught instanceof Error ? caught.message : '保存失败');
    } finally {
      submittingRef.current = false;
      setBusy(false);
    }
  };

  return (
    <form className={styles.form} aria-busy={busy} autoComplete="off" onSubmit={submit}>
      <div className={styles.head}>
        <h2 className={styles.heading}>{mode === 'new' ? '新建条目' : `编辑「${initialItem!.title}」`}</h2>
      </div>

      {formBlocked && (
        <div className={styles.concurrentWarning} role="alert">
          <AlertTriangle size={17} aria-hidden />
          <div>
            <strong>{currentConflict?.reason === 'metadata_format_outdated' ? '应用已更新，需要重新编辑' : '这条记录刚刚有了新修改'}</strong>
            <span>{currentConflict?.reason === 'metadata_format_outdated'
              ? '系统已暂停旧版保存，避免错误写入。你的输入仍保留在本页；请先复制需要保留的部分，再取消编辑并重新打开条目。'
              : '系统已暂停保存，避免覆盖他人的内容。你的输入仍保留在本页；请先复制需要保留的部分，再取消编辑并查看最新内容。'}</span>
          </div>
        </div>
      )}

      {mode === 'new' && (
        <div className={styles.field}>
          <label className={styles.label}>类型</label>
          <SegmentedControl label="条目类型" value={kind} options={KIND_OPTIONS} onChange={handleKindChange} />
        </div>
      )}

      <div className={styles.field}>
        <label className={styles.label} htmlFor="f-title">标题 *</label>
        <input
          id="f-title"
          name="item-title"
          className={styles.input}
          {...bindIntentionalField(title)}
          autoComplete="off"
          autoFocus
        />
      </div>

      <div className={styles.field}>
        <label className={styles.label} htmlFor="f-folder">目录（可选）</label>
        <select
          id="f-folder"
          name="item-folder"
          className={styles.input}
          value={folderPath}
          onChange={(event) => {
            setFolderPath(event.target.value);
            setFolderTouched(true);
          }}
        >
          <option value="">未分类</option>
          {folderOptions.map((path) => <option key={path} value={path}>{path}</option>)}
        </select>
      </div>

      {kind !== 'secure_note' && (
        <div className={styles.field}>
          <label className={styles.label} htmlFor="f-username">{presentation.auxiliaryLabel}</label>
          <input
            id="f-username"
            name="item-auxiliary"
            className={styles.input}
            {...bindIntentionalField(username)}
            autoComplete="off"
            placeholder={presentation.auxiliaryHint ?? undefined}
          />
        </div>
      )}

      {kind === 'login' && (
        <div className={styles.field}>
          <label className={styles.label} htmlFor="f-origin">网址（可选）</label>
          <input
            id="f-origin"
            name="item-url"
            className={styles.input}
            {...bindIntentionalField(loginUrl)}
            autoComplete="off"
            placeholder="https://portal.example.test"
            maxLength={LOGIN_URL_MAX_LENGTH}
          />
        </div>
      )}

      {kind === 'api_token' && (
        <div className={styles.field}>
          <label className={styles.label} htmlFor="f-linked-login">关联账号密码（可选）</label>
          <select
            id="f-linked-login"
            name="item-linked-login"
            className={styles.input}
            value={linkedLoginItemId}
            onChange={(event) => {
              setLinkedLoginItemId(event.target.value);
              setLinkedLoginTouched(true);
            }}
          >
            <option value="">不关联</option>
            {loginOptions.map((login) => (
              <option key={login.id} value={login.id}>
                {login.title}{login.username ? ` · ${login.username}` : ''}
              </option>
            ))}
          </select>
        </div>
      )}

      {kind !== 'secure_note' && (
        <div className={styles.field}>
          <label className={styles.label} htmlFor="f-description">说明（可选）</label>
          <textarea
            id="f-description"
            name="item-description"
            className={styles.textarea}
            {...bindIntentionalField(description)}
            rows={3}
            maxLength={ITEM_DESCRIPTION_MAX_LENGTH}
            autoComplete="off"
            placeholder={kind === 'login'
              ? '主机/IP、端口、实例/库名、环境、用途、归属等；不要填写密码或密钥'
              : '账号归属、用途、申请来源等；不要填写密码或密钥'}
          />
        </div>
      )}

      {mode === 'edit' && (
        <label className={styles.secretToggle}>
          <input
            type="checkbox"
            checked={replaceSecret}
            onChange={(event) => handleReplaceSecret(event.target.checked)}
          />
          {secretToggleLabel(kind, initialItem?.secretState)}
        </label>
      )}

      {secretEditorVisible && (
        <div className={styles.field}>
          <label className={styles.label} htmlFor="f-secret">
            {presentation.secretLabel}{mode === 'new' ? (kind === 'login' ? '（可选）' : ' *') : ''}
          </label>
          {isNote ? (
            <textarea
              id="f-secret"
              name="item-sensitive-content"
              className={styles.textarea}
              {...bindIntentionalField(secret)}
              rows={6}
              readOnly={!secret.activated}
              autoComplete="off"
            />
          ) : (
            <input
              id="f-secret"
              name="item-new-secret"
              className={styles.input}
              {...bindIntentionalField(secret)}
              type="password"
              readOnly={!secret.activated}
              autoComplete="new-password"
              spellCheck={false}
              style={{ fontFamily: 'var(--font-mono)' }}
            />
          )}
          {kind === 'login' && <PasswordGenerator onUse={secret.setFromUserAction} />}
        </div>
      )}

      <div className={styles.field}>
        <label className={styles.label} htmlFor="f-tags">标签（逗号分隔）</label>
        <input
          id="f-tags"
          name="item-tags"
          className={styles.input}
          {...bindIntentionalField(tags)}
          autoComplete="off"
        />
      </div>

      <div className={styles.rowFields}>
        <label className={styles.checkbox}>
          <input
            type="checkbox"
            checked={highSensitivity}
            onChange={(event) => {
              setHighSensitivity(event.target.checked);
              setSensitivityTouched(true);
            }}
          />
          标记为高敏
        </label>
        <label className={styles.checkbox}>
          <input
            type="checkbox"
            checked={favorite}
            onChange={(event) => {
              setFavorite(event.target.checked);
              setFavoriteTouched(true);
            }}
          />
          收藏
        </label>
      </div>

      {error && !formBlocked && <div className={styles.error} role="alert">{error}</div>}

      <div className={styles.footer}>
        <ActionButton
          label="取消"
          variant="secondary"
          onClick={onClose}
          disabled={busy}
        />
        <ActionButton
          type="submit"
          label={busy ? '保存中…' : '保存'}
          icon={<Save size={16} />}
          disabled={busy || formBlocked || !hasChanges}
          title={formBlocked ? '请先查看这条记录的最新内容' : undefined}
        />
      </div>
    </form>
  );
}

type IntentionalField = ReturnType<typeof useIntentionalTextField>;

function bindIntentionalField(field: IntentionalField) {
  return {
    value: field.value,
    onChange: field.onChange,
    onKeyDown: field.onKeyDown,
    onKeyUp: field.onKeyUp,
    onBlur: field.onBlur,
    onPaste: field.onPaste,
    onCut: field.onCut,
    onDrop: field.onDrop,
    onCompositionStart: field.onCompositionStart,
    onCompositionEnd: field.onCompositionEnd,
  };
}

function parseTags(value: string): string[] {
  return value
    .split(/[,，]/)
    .map((tag) => tag.trim())
    .filter(Boolean)
    .slice(0, 20);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function secretToggleLabel(kind: ItemKind, secretState?: DecryptedItemMeta['secretState']): string {
  if (kind === 'secure_note') return '同时更新备注正文';
  if (kind === 'api_token') return '同时更换密钥 / Token';
  return secretState === 'absent' ? '添加密码' : '同时更换密码';
}
