import { useEffect, useMemo, useRef, useState } from 'react';
import { AlertTriangle, ArrowDown, ArrowUp, Plus, Save, Trash2, WandSparkles } from 'lucide-react';
import type { DecryptedItemMeta, DecryptedItemMetaPatch } from '@mima/client-core';
import type { ItemKind } from '@mima/contracts';
import {
  folderContainsPath,
  getItemPresentation,
  ITEM_DESCRIPTION_MAX_LENGTH,
  LOGIN_URL_MAX_LENGTH,
  LOGIN_URLS_MAX_COUNT,
  materializeVaultDirectories,
  normalizeFolderPath,
  normalizeLoginUrls,
  normalizeOrigin,
} from '@mima/domain';
import { useIntentionalTextField } from '../hooks/useIntentionalTextField.ts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi, type NewItemPreset } from '../state/ui-store.ts';
import { ActionButton } from './ActionButton.tsx';
import { IconButton } from './IconButton.tsx';
import { ItemKindMark } from './ItemKindMark.tsx';
import { PasswordGenerator } from './PasswordGenerator.tsx';
import { SegmentedControl } from './SegmentedControl.tsx';
import styles from './ItemForm.module.css';

const KIND_OPTIONS: { value: ItemKind; label: string; icon: React.ReactNode }[] = (
  ['login', 'api_token', 'secure_note'] as const
).map((value) => ({
  value,
  label: getItemPresentation(value).kindLabel,
  icon: <ItemKindMark kind={value} compact />,
}));

const CONCURRENT_EDIT_MESSAGE = '这条记录刚刚有了新修改。系统已暂停保存，避免覆盖他人的内容。你的输入仍保留在本页；请先复制需要保留的部分，再取消编辑并查看最新内容';

type OptionalField = 'description' | 'linkedLogin' | 'tags' | 'favorite' | 'sensitivity';
type UrlEntry = { id: string; value: string };

let urlEntrySequence = 0;

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
  const setItemDraftState = useUi((state) => state.setItemDraftState);
  const initialItemRef = useRef(item);
  const initialItem = initialItemRef.current;

  const targetVaultId = initialItem?.vaultId ?? preset?.vaultId ?? ui.selectedVaultId;
  const [kind, setKind] = useState<ItemKind>(initialItem?.kind ?? preset?.kind ?? 'login');
  const [kindTouched, setKindTouched] = useState(false);
  const [baseVersion] = useState<number | undefined>(initialItem?.version);
  const title = useIntentionalTextField(initialItem?.title ?? '');
  const username = useIntentionalTextField(initialItem?.username ?? '');
  const description = useIntentionalTextField(initialItem?.description ?? '');
  const tags = useIntentionalTextField(initialItem?.tags.join(', ') ?? '');
  const secret = useIntentionalTextField('');
  const [urlEntries, setUrlEntries] = useState<UrlEntry[]>(() => initialUrlEntries(initialItem));
  const [urlsTouched, setUrlsTouched] = useState(false);
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
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [optionalPickerOpen, setOptionalPickerOpen] = useState(false);
  const [visibleOptionalFields, setVisibleOptionalFields] = useState<Set<OptionalField>>(
    () => new Set(preset?.linkedLoginItemId ? ['linkedLogin'] : []),
  );
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submittingRef = useRef(false);

  const offline = connection !== 'online';
  const isNote = kind === 'secure_note';
  const presentation = getItemPresentation(kind);
  const secretEditorVisible = mode === 'new' || replaceSecret;
  const liveItem = initialItem ? items[initialItem.id] : undefined;
  const formStale = mode === 'edit' && Boolean(initialItem) && (!liveItem || liveItem.version !== baseVersion);
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
  const rawLoginUrls = kind === 'login'
    ? urlEntries.map((entry) => entry.value.trim()).filter(Boolean)
    : [];
  const normalizedLoginUrls = normalizeLoginUrls(rawLoginUrls);
  const normalizedLoginUrl = normalizedLoginUrls?.[0] ?? null;
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
    if (kind === 'login' && urlsTouched && normalizedLoginUrls !== null) {
      const baselineUrls = getInitialLoginUrls(initialItem);
      if (!sameStrings(normalizedLoginUrls, baselineUrls)) {
        patch.loginUrls = normalizedLoginUrls;
        patch.loginUrl = normalizedLoginUrl;
        patch.origin = normalizedOrigin;
      }
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
    || urlsTouched
    || folderTouched
    || description.touched
    || linkedLoginTouched
    || tags.touched
    || sensitivityTouched
    || favoriteTouched
    || secret.touched;
  const hasChanges = mode === 'new' ? newDraftTouched : changesSecret || Object.keys(editPatch).length > 0;

  useEffect(() => {
    setItemDraftState(hasChanges, busy);
  }, [busy, hasChanges, setItemDraftState]);

  useEffect(() => () => {
    useUi.getState().discardItemDraft();
  }, []);

  const validate = (): string | null => {
    if (!normalizedTitle) return '标题不能为空';
    if ((mode === 'new' || folderTouched) && folderPath.trim() && normalizedFolderPath === null) {
      return '目录格式不正确，请使用 / 分层，最多 5 级且每级不超过 40 个字符';
    }
    if ((mode === 'new' || urlsTouched) && kind === 'login' && normalizedLoginUrls === null) {
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
    description.reset();
    secret.reset();
    setUrlEntries([createUrlEntry('')]);
    setUrlsTouched(false);
    setLinkedLoginItemId('');
    setLinkedLoginTouched(false);
    setVisibleOptionalFields(new Set());
    setOptionalPickerOpen(false);
    setGeneratorOpen(false);
  };

  const handleReplaceSecret = (enabled: boolean) => {
    setReplaceSecret(enabled);
    setGeneratorOpen(false);
    if (!enabled) secret.reset();
  };

  const updateUrlEntry = (id: string, value: string) => {
    setUrlEntries((current) => current.map((entry) => entry.id === id ? { ...entry, value } : entry));
    setUrlsTouched(true);
  };

  const addUrlEntry = () => {
    if (urlEntries.length >= LOGIN_URLS_MAX_COUNT) return;
    setUrlEntries((current) => [...current, createUrlEntry('')]);
  };

  const removeUrlEntry = (id: string) => {
    setUrlEntries((current) => {
      const next = current.filter((entry) => entry.id !== id);
      return next.length > 0 ? next : [createUrlEntry('')];
    });
    setUrlsTouched(true);
  };

  const moveUrlEntry = (index: number, delta: -1 | 1) => {
    const target = index + delta;
    if (target < 0 || target >= urlEntries.length) return;
    setUrlEntries((current) => {
      const next = [...current];
      [next[index], next[target]] = [next[target]!, next[index]!];
      return next;
    });
    setUrlsTouched(true);
  };

  const addOptionalField = (field: OptionalField) => {
    setVisibleOptionalFields((current) => new Set([...current, field]));
  };

  const assertNoConflict = () => {
    if (initialItem && store.getState().conflicts[initialItem.id]) throw new Error(CONCURRENT_EDIT_MESSAGE);
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
    let savedSuccessfully = false;
    setError(null);
    setBusy(true);
    setItemDraftState(hasChanges, true);
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
          loginUrls: normalizedLoginUrls ?? [],
          folderPath: normalizedFolderPath,
          description: normalizedDescription,
          linkedLoginItemId: normalizedLinkedLoginItemId,
          tags: normalizedTags,
          favorite,
          sensitivity: highSensitivity ? 'high' : 'medium',
          secretValue: kind === 'login' && (!secret.touched || secret.value.length === 0) ? null : secret.value,
        });
        secret.reset();
        savedSuccessfully = true;
        setItemDraftState(false, false);
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
      savedSuccessfully = true;
      setItemDraftState(false, false);
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
      setItemDraftState(savedSuccessfully ? false : hasChanges, false);
    }
  };

  const optionalFields = optionalFieldsFor(kind);

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
          <SegmentedControl label="条目类型" value={kind} options={KIND_OPTIONS} onChange={handleKindChange} layout="equal" />
        </div>
      )}

      <div className={styles.field}>
        <label className={styles.label} htmlFor="f-title">标题 *</label>
        <input id="f-title" name="item-title" className={styles.input} {...bindIntentionalField(title)} autoComplete="off" autoFocus />
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
          {folderOptions.map((path) => (
            <option key={path} value={path} title={path}>{directoryOptionLabel(path)}</option>
          ))}
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

      {mode === 'edit' && (
        <label className={styles.secretToggle}>
          <input type="checkbox" checked={replaceSecret} onChange={(event) => handleReplaceSecret(event.target.checked)} />
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
              rows={5}
              readOnly={!secret.activated}
              autoComplete="off"
            />
          ) : (
            <div className={styles.secretInputWrap}>
              <input
                id="f-secret"
                name="item-new-secret"
                className={styles.input}
                {...bindIntentionalField(secret)}
                type="password"
                readOnly={!secret.activated}
                autoComplete="new-password"
                spellCheck={false}
              />
              {kind === 'login' && (
                <button
                  type="button"
                  className={[styles.generatorToggle, generatorOpen ? styles.generatorToggleActive : ''].join(' ')}
                  aria-label="生成密码"
                  aria-expanded={generatorOpen}
                  title="生成密码"
                  onClick={() => setGeneratorOpen((open) => !open)}
                >
                  <WandSparkles size={16} aria-hidden />
                </button>
              )}
            </div>
          )}
          {kind === 'login' && generatorOpen && (
            <PasswordGenerator onUse={(value) => {
              secret.setFromUserAction(value);
              setGeneratorOpen(false);
            }} />
          )}
        </div>
      )}

      {kind === 'login' && (
        <div className={styles.urlSection} aria-label="网址">
          {urlEntries.map((entry, index) => (
            <UrlFieldRow
              key={entry.id}
              entry={entry}
              index={index}
              count={urlEntries.length}
              onValueChange={updateUrlEntry}
              onMove={moveUrlEntry}
              onRemove={removeUrlEntry}
            />
          ))}
          {urlEntries.length < LOGIN_URLS_MAX_COUNT && (
            <button type="button" className={styles.addUrl} onClick={addUrlEntry}>
              <Plus size={14} aria-hidden />
              添加网址
            </button>
          )}
        </div>
      )}

      {visibleOptionalFields.has('linkedLogin') && kind === 'api_token' && (
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
              <option key={login.id} value={login.id}>{login.title}{login.username ? ` · ${login.username}` : ''}</option>
            ))}
          </select>
        </div>
      )}

      {visibleOptionalFields.has('description') && kind !== 'secure_note' && (
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

      {visibleOptionalFields.has('tags') && (
        <div className={styles.field}>
          <label className={styles.label} htmlFor="f-tags">标签（逗号分隔）</label>
          <input id="f-tags" name="item-tags" className={styles.input} {...bindIntentionalField(tags)} autoComplete="off" />
        </div>
      )}

      {(visibleOptionalFields.has('favorite') || visibleOptionalFields.has('sensitivity')) && (
        <div className={styles.rowFields}>
          {visibleOptionalFields.has('sensitivity') && (
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
          )}
          {visibleOptionalFields.has('favorite') && (
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
          )}
        </div>
      )}

      <div className={styles.optionalFields}>
        <button
          type="button"
          className={styles.addField}
          aria-expanded={optionalPickerOpen}
          onClick={() => setOptionalPickerOpen((open) => !open)}
        >
          <Plus size={14} aria-hidden />
          添加字段
        </button>
        {optionalPickerOpen && (
          <div className={styles.optionalPicker} role="group" aria-label="可添加字段">
            {optionalFields.filter((field) => !visibleOptionalFields.has(field)).map((field) => (
              <button key={field} type="button" onClick={() => addOptionalField(field)}>
                {optionalFieldLabel(field)}{optionalFieldHasValue(field, initialItem) ? '（已填写）' : ''}
              </button>
            ))}
            {optionalFields.every((field) => visibleOptionalFields.has(field)) && <span>已显示全部字段</span>}
          </div>
        )}
      </div>

      {error && !formBlocked && <div className={styles.error} role="alert">{error}</div>}

      <div className={styles.footer}>
        <ActionButton label="取消" variant="secondary" onClick={onClose} disabled={busy} />
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

function UrlFieldRow({
  entry,
  index,
  count,
  onValueChange,
  onMove,
  onRemove,
}: {
  entry: UrlEntry;
  index: number;
  count: number;
  onValueChange: (id: string, value: string) => void;
  onMove: (index: number, delta: -1 | 1) => void;
  onRemove: (id: string) => void;
}) {
  const field = useIntentionalTextField(entry.value, (value) => onValueChange(entry.id, value));
  const label = index === 0 ? '网址（主网址，可选）' : `备用网址 ${index + 1}`;
  return (
    <div className={styles.urlField}>
      <label className={styles.label} htmlFor={`f-url-${entry.id}`}>{label}</label>
      <div className={styles.urlInputRow}>
        <input
          id={`f-url-${entry.id}`}
          name={`item-url-${index + 1}`}
          className={styles.input}
          {...bindIntentionalField(field)}
          autoComplete="off"
          placeholder="https://portal.example.test"
          maxLength={LOGIN_URL_MAX_LENGTH}
        />
        {count > 1 && (
          <>
            <IconButton label="上移网址" onClick={() => onMove(index, -1)} disabled={index === 0}>
              <ArrowUp size={14} />
            </IconButton>
            <IconButton label="下移网址" onClick={() => onMove(index, 1)} disabled={index === count - 1}>
              <ArrowDown size={14} />
            </IconButton>
            <IconButton label="删除网址" onClick={() => onRemove(entry.id)} danger>
              <Trash2 size={14} />
            </IconButton>
          </>
        )}
      </div>
    </div>
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

function createUrlEntry(value: string): UrlEntry {
  urlEntrySequence += 1;
  return { id: `url-${urlEntrySequence}`, value };
}

function initialUrlEntries(item?: DecryptedItemMeta): UrlEntry[] {
  const urls = item ? getInitialLoginUrls(item) : [];
  return (urls.length > 0 ? urls : ['']).map(createUrlEntry);
}

function getInitialLoginUrls(item: DecryptedItemMeta): string[] {
  const raw = item.loginUrls?.length
    ? item.loginUrls
    : [item.loginUrl ?? item.origin].filter((url): url is string => Boolean(url));
  return normalizeLoginUrls(raw) ?? [];
}

function directoryOptionLabel(path: string): string {
  const segments = path.split('/');
  return `${'\u00a0'.repeat(Math.max(0, segments.length - 1) * 4)}${segments.at(-1)}`;
}

function optionalFieldsFor(kind: ItemKind): OptionalField[] {
  if (kind === 'api_token') return ['linkedLogin', 'description', 'tags', 'favorite', 'sensitivity'];
  if (kind === 'secure_note') return ['tags', 'favorite', 'sensitivity'];
  return ['description', 'tags', 'favorite', 'sensitivity'];
}

function optionalFieldLabel(field: OptionalField): string {
  if (field === 'description') return '说明';
  if (field === 'linkedLogin') return '关联账号密码';
  if (field === 'tags') return '标签';
  if (field === 'favorite') return '收藏';
  return '高敏标记';
}

function optionalFieldHasValue(field: OptionalField, item?: DecryptedItemMeta): boolean {
  if (!item) return false;
  if (field === 'description') return Boolean(item.description?.trim());
  if (field === 'linkedLogin') return Boolean(item.linkedLoginItemId);
  if (field === 'tags') return item.tags.length > 0;
  if (field === 'favorite') return item.favorite;
  return item.sensitivity === 'high';
}

function parseTags(value: string): string[] {
  return value.split(/[,，]/).map((tag) => tag.trim()).filter(Boolean).slice(0, 20);
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function secretToggleLabel(kind: ItemKind, secretState?: DecryptedItemMeta['secretState']): string {
  if (kind === 'secure_note') return '同时更新备注正文';
  if (kind === 'api_token') return '同时更换密钥 / Token';
  return secretState === 'absent' ? '添加密码' : '同时更换密码';
}
