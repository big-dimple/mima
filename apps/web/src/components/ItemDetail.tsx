import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle, ChevronRight, Copy, ExternalLink, Eye, EyeOff, FolderInput, History, KeyRound, Link2,
  Pencil, Plus, Star, StarOff, Trash2, X,
} from 'lucide-react';
import type { DecryptedItemMeta } from '@mima/client-core';
import type { SecretVersionInfo } from '@mima/contracts';
import {
  getItemPresentation,
  getVisibleItemAuxiliary,
  normalizeLoginUrl,
  resolveEffectiveRole,
  canEditItems,
  canReveal,
} from '@mima/domain';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { useLease } from '../hooks/useLease.ts';
import { useTransientText } from '../hooks/useTransientText.ts';
import { copyWithTimedClear } from '../utils/clipboard.ts';
import { IconButton, IconLink } from './IconButton.tsx';
import { ActionButton } from './ActionButton.tsx';
import { SecretField } from './SecretField.tsx';
import { ItemForm } from './ItemForm.tsx';
import { MoveToFolderDialog } from './MoveToFolderDialog.tsx';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import { ItemKindBadge } from './ItemKindMark.tsx';
import styles from './ItemDetail.module.css';

export function ItemDetail() {
  const ui = useUi();
  const item = useMeta((s) => (ui.selectedItemId ? s.items[ui.selectedItemId] : undefined));

  if (ui.editing === 'new') {
    return (
      <main className={styles.pane} aria-label="新建条目" id="main-content">
        <ItemForm mode="new" preset={ui.newItemPreset} onClose={() => ui.setEditing(null)} />
      </main>
    );
  }
  if (ui.editing && item && ui.editing === item.id) {
    return (
      <main className={styles.pane} aria-label="编辑条目" id="main-content">
        <ItemForm mode="edit" item={item} onClose={() => ui.setEditing(null)} />
      </main>
    );
  }
  if (!item) {
    return (
      <main className={styles.pane} aria-label="详情" id="main-content">
        <div className={styles.empty}>
          <p>选择一个条目查看详情</p>
          <p className={styles.emptyHint}>↑↓ 选择 · Enter 打开 · / 搜索</p>
        </div>
      </main>
    );
  }
  return <ItemView item={item} />;
}

function ItemView({ item }: { item: DecryptedItemMeta }) {
  const { actions, outbox, zeroKnowledge } = useApp();
  const ui = useUi();
  const user = useMeta((s) => s.user)!;
  const vault = useMeta((s) => s.vaults[item.vaultId]);
  const memberships = useMeta((s) => s.memberships[item.vaultId]);
  const conflict = useMeta((s) => s.conflicts[item.id]);
  const connection = useMeta((s) => s.connection);
  const pending = useMeta((s) => !!s.pendingItemIds[item.id]);
  const items = useMeta((s) => s.items);
  const toast = useUi((s) => s.toast);
  const [showHistory, setShowHistory] = useState(false);
  const [moveOpen, setMoveOpen] = useState(false);
  const [conflictBusy, setConflictBusy] = useState<'refresh' | 'discard' | null>(null);
  const presentation = getItemPresentation(item.kind);
  const hasSecret = item.secretState === 'present';
  const auxiliary = getVisibleItemAuxiliary(item.kind, item.username);
  const websiteUrls = item.kind === 'login'
    ? (item.loginUrls?.length ? item.loginUrls : [item.loginUrl ?? item.origin].filter((url): url is string => Boolean(url)))
    : [];
  const linkedLogin = useMemo(() => {
    if (item.kind !== 'api_token' || !item.linkedLoginItemId) return null;
    const candidate = items[item.linkedLoginItemId];
    return candidate?.kind === 'login' && candidate.vaultId === item.vaultId ? candidate : null;
  }, [item.kind, item.linkedLoginItemId, item.vaultId, items]);
  const linkedApiCredentials = useMemo(() => {
    if (item.kind !== 'login') return [];
    return Object.values(items)
      .filter((candidate) => (
        candidate.kind === 'api_token' &&
        candidate.vaultId === item.vaultId &&
        candidate.linkedLoginItemId === item.id
      ))
      .sort((left, right) => left.title.localeCompare(right.title, 'zh-CN'));
  }, [item.id, item.kind, item.vaultId, items]);

  const role = useMemo(
    () =>
      vault?.kind === 'personal'
        ? ('owner' as const)
        : resolveEffectiveRole(memberships ?? [], { userId: user.id, groups: user.groups }),
    [vault, memberships, user],
  );
  const editable = canEditItems(role);
  const revealable = canReveal(role);

  const toggleFavorite = () => {
    void actions.updateItemMeta(item.id, { favorite: !item.favorite }).catch(() => undefined);
  };

  const remove = async () => {
    const confirmed = await useUi.getState().requestConfirm({
      title: '删除条目',
      body: `确定删除「${item.title}」？删除后其他成员将同步移除。`,
      confirmText: '删除',
      cancelText: '取消',
      danger: true,
    });
    if (!confirmed) return;
    actions.deleteItem(item.id);
    ui.selectItem(null);
  };

  const copyAuxiliary = async () => {
    if (!auxiliary || !presentation.copyAuxiliaryLabel) return;
    await copyWithTimedClear(auxiliary);
    toast('info', `${presentation.auxiliaryLabel}已复制`);
  };

  const copyWebsiteUrl = async (websiteUrl: string) => {
    await copyWithTimedClear(websiteUrl);
    toast('info', '网址已复制');
  };

  const refreshServerVersion = async () => {
    setConflictBusy('refresh');
    try {
      await zeroKnowledge.refresh();
      toast('info', '已加载服务器上的最新版本；你尚未提交的修改仍保留在这台设备');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '服务器版本刷新失败');
    } finally {
      setConflictBusy(null);
    }
  };

  const discardLocalCandidate = async () => {
    if (!conflict?.commandId) {
      actions.resolveConflict(item.id);
      return;
    }
    const confirmed = await useUi.getState().requestConfirm({
      title: '放弃本地修改',
      body: `确定放弃「${item.title}」在当前设备上尚未提交的修改？此操作不能撤销，服务器上的版本不会改变。`,
      confirmText: '放弃本地修改',
      cancelText: '继续保留',
      danger: true,
    });
    if (!confirmed) return;
    setConflictBusy('discard');
    try {
      const discarded = await outbox.discardConflict(conflict.commandId);
      if (discarded === 0) throw new Error('本地修改已经不存在，请刷新页面');
      actions.resolveConflict(item.id);
      await zeroKnowledge.refresh();
      toast('info', '已放弃本地修改并保留服务器版本');
    } catch (error) {
      toast('error', error instanceof Error ? error.message : '放弃本地修改失败');
    } finally {
      setConflictBusy(null);
    }
  };

  return (
    <main className={styles.pane} aria-label={`条目详情：${item.title}`} id="main-content">
      <div className={styles.header}>
        <div className={styles.titleRow}>
          <h2 className={styles.title}>{item.title}</h2>
          <ItemKindBadge kind={item.kind} />
          {pending && <span className={styles.pendingBadge}>待同步</span>}
        </div>
        <div className={styles.headerActions}>
          {editable && (
            <ActionButton
              label="编辑"
              icon={<Pencil size={16} />}
              onClick={() => ui.setEditing(item.id)}
            />
          )}
          <IconButton
            label={item.favorite ? '取消收藏' : '收藏'}
            onClick={toggleFavorite}
            disabled={!editable}
          >
            {item.favorite ? <StarOff size={15} /> : <Star size={15} />}
          </IconButton>
          {hasSecret && (
            <IconButton label="查看版本历史" onClick={() => setShowHistory((v) => !v)} active={showHistory}>
              <History size={15} />
            </IconButton>
          )}
          {editable && (
            <IconButton label="删除" onClick={remove} danger>
              <Trash2 size={15} />
            </IconButton>
          )}
        </div>
      </div>

      {conflict && (
        <div className={styles.conflict} role="alert" aria-busy={conflictBusy !== null}>
          <AlertTriangle size={15} aria-hidden />
          <div className={styles.conflictBody}>
            <div>
              <strong>{conflict.reason === 'metadata_format_outdated' ? '应用已更新，需要重新编辑' : '发现另一份更新'}</strong>
              {conflict.reason === 'metadata_format_outdated'
                ? '：系统已暂停旧版保存，避免错误写入。请放弃旧版草稿，再重新打开条目完成修改。'
                : `：这条记录已经有了更新。${conflict.commandId
                  ? ' 为避免覆盖同事的内容，当前设备仍保留加密草稿；系统不会自行拼接密码、Token 或备注。'
                  : ' 当前显示最新内容；密码、Token 或备注不会被系统自行合并。'}`}
            </div>
            {conflict.commandId && connection !== 'online' && (
              <span className={styles.conflictHint}>重新联网后才能加载服务器上的最新版本或放弃本地修改。</span>
            )}
          </div>
          <div className={styles.conflictActions}>
            {conflict.commandId ? (
              <>
                <button
                  className={styles.conflictButton}
                  type="button"
                  disabled={connection !== 'online' || conflictBusy !== null}
                  onClick={() => void refreshServerVersion()}
                >
                  {conflictBusy === 'refresh'
                    ? '正在刷新…'
                    : conflict.reason === 'metadata_format_outdated' ? '查看当前内容' : '查看最新内容'}
                </button>
                <button
                  className={styles.conflictDiscard}
                  type="button"
                  disabled={connection !== 'online' || conflictBusy !== null}
                  onClick={() => void discardLocalCandidate()}
                >
                  {conflictBusy === 'discard'
                    ? '正在放弃…'
                    : conflict.reason === 'metadata_format_outdated' ? '放弃旧版草稿' : '放弃本地修改'}
                </button>
              </>
            ) : (
              <button className={styles.conflictButton} type="button" onClick={() => actions.resolveConflict(item.id)}>
                保留最新内容
              </button>
            )}
          </div>
        </div>
      )}

      <dl className={styles.fields}>
        <div className={styles.fieldRow}>
          <dt>所在库</dt>
          <dd>{vault?.name ?? '—'}</dd>
        </div>
        <div className={styles.fieldRow}>
          <dt>目录</dt>
          <dd className={styles.withAction}>
            {item.folderPath ? (
              <button
                type="button"
                className={styles.folderPath}
                onClick={() => {
                  ui.selectVault(item.vaultId);
                  ui.selectFolder(item.folderPath!);
                }}
              >
                {item.folderPath}
              </button>
            ) : (
              <span>未分类</span>
            )}
            {editable && (
              <IconButton label="移动到目录" onClick={() => setMoveOpen(true)}>
                <FolderInput size={13} />
              </IconButton>
            )}
          </dd>
        </div>
        {auxiliary && presentation.auxiliaryLabel && presentation.copyAuxiliaryLabel && (
          <div className={styles.fieldRow}>
            <dt>{presentation.auxiliaryLabel}</dt>
            <dd className={styles.withAction}>
              <span className={styles.mono}>{auxiliary}</span>
              <IconButton label={presentation.copyAuxiliaryLabel} onClick={copyAuxiliary}>
                <Copy size={13} />
              </IconButton>
            </dd>
          </div>
        )}
        {websiteUrls.map((websiteUrl, index) => {
          const externalWebsiteUrl = normalizeLoginUrl(websiteUrl);
          return (
            <div className={[styles.fieldRow, styles.fieldRowMultiline].join(' ')} key={`${index}:${websiteUrl}`}>
              <dt>{index === 0 ? '网址' : '备用网址'}</dt>
              <dd className={styles.websiteValue}>
                <span className={styles.mono} data-testid="website-url-value">{websiteUrl}</span>
                <span className={styles.websiteActions}>
                  <IconButton label={`复制${index === 0 ? '网址' : `备用网址 ${index + 1}`}`} onClick={() => void copyWebsiteUrl(websiteUrl)}>
                    <Copy size={13} />
                  </IconButton>
                  {externalWebsiteUrl && (
                    <IconLink label={`打开${index === 0 ? '网址' : `备用网址 ${index + 1}`}`} href={externalWebsiteUrl}>
                      <ExternalLink size={13} />
                    </IconLink>
                  )}
                </span>
              </dd>
            </div>
          );
        })}
        {item.kind === 'api_token' && (
          <div className={styles.fieldRow}>
            <dt>关联账号密码</dt>
            <dd>
              {linkedLogin ? (
                <button
                  type="button"
                  className={styles.relatedLink}
                  onClick={() => ui.selectItem(linkedLogin.id)}
                >
                  <Link2 size={13} aria-hidden />
                  <span>{linkedLogin.title}</span>
                </button>
              ) : item.linkedLoginItemId ? (
                <span className={styles.missingRelation}>关联账号密码已不存在</span>
              ) : (
                <span>未关联</span>
              )}
            </dd>
          </div>
        )}
        {item.kind !== 'secure_note' && item.description?.trim() && (
          <div className={[styles.fieldRow, styles.fieldRowMultiline].join(' ')}>
            <dt>说明</dt>
            <dd className={styles.description}>{item.description}</dd>
          </div>
        )}
        {item.tags.length > 0 && (
          <div className={[styles.fieldRow, styles.fieldRowMultiline].join(' ')}>
            <dt>标签</dt>
            <dd className={styles.tags}>
              {item.tags.map((t) => (
                <button key={t} className={styles.tag} onClick={() => ui.setTagFilter(t)}>
                  {t}
                </button>
              ))}
            </dd>
          </div>
        )}
        {item.sensitivity === 'high' && (
          <div className={styles.fieldRow}>
            <dt>敏感标记</dt>
            <dd><span className={[styles.sens, styles.sens_high].join(' ')}>高敏</span></dd>
          </div>
        )}
      </dl>

      {item.kind === 'login' && (
        <section className={styles.relations} aria-labelledby="linked-api-credentials-heading">
          <div className={styles.relationsHeader}>
            <h3 id="linked-api-credentials-heading">关联 API 凭证</h3>
            {editable && (
              <ActionButton
                label="新增关联凭证"
                icon={<Plus size={15} />}
                variant="secondary"
                onClick={() => ui.startNewItem({
                  kind: 'api_token',
                  vaultId: item.vaultId,
                  linkedLoginItemId: item.id,
                })}
              />
            )}
          </div>
          {linkedApiCredentials.length > 0 ? (
            <div className={styles.relationList}>
              {linkedApiCredentials.map((credential) => (
                <button
                  key={credential.id}
                  type="button"
                  className={styles.relationRow}
                  onClick={() => ui.selectItem(credential.id)}
                >
                  <KeyRound size={15} aria-hidden />
                  <span className={styles.relationBody}>
                    <strong>{credential.title}</strong>
                    {credential.username && <span>{credential.username}</span>}
                  </span>
                  <ChevronRight size={15} aria-hidden />
                </button>
              ))}
            </div>
          ) : (
            <p className={styles.emptyRelations}>暂无关联凭证</p>
          )}
        </section>
      )}

      {!hasSecret ? (
        <div className={styles.secretAbsent} role="status">
          <KeyRound size={16} aria-hidden />
          <span>未保存密码</span>
        </div>
      ) : revealable ? (
        <SecretField itemId={item.id} kind={item.kind} secretVersion={item.secretVersion} />
      ) : (
        <div className={styles.noReveal}>
          当前权限（{role === 'auditor' ? '审计' : '无权限'}）不能查看密码或敏感内容。
        </div>
      )}

      {hasSecret && showHistory && <VersionHistory item={item} revealable={revealable} />}

      <div className={styles.meta}>
        条目版本 v{item.version}{hasSecret ? ` · 内容版本 v${item.secretVersion}` : ' · 未保存密码'} · 更新于 {formatTime(item.updatedAt)} · {displayActor(item.updatedBy, user)}
      </div>

      <MoveToFolderDialog open={moveOpen} item={item} onOpenChange={setMoveOpen} />
    </main>
  );
}

function VersionHistory({ item, revealable }: { item: DecryptedItemMeta; revealable: boolean }) {
  const { api } = useApp();
  const [versions, setVersions] = useState<SecretVersionInfo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);

  useEffect(() => {
    setVersions(null);
    setError(null);
    api.itemVersions(item.id)
      .then(setVersions)
      .catch((caught) => setError(caught instanceof Error ? caught.message : '版本历史加载失败'));
  }, [api, item.id, item.secretVersion, retryKey]);

  return (
    <div className={styles.history}>
      <div className={styles.historyTitle}>修改记录</div>
      {error && (
        <ErrorState
          message={error}
          onRetry={() => setRetryKey((value) => value + 1)}
        />
      )}
      {!error && versions === null && <LoadingState label="正在加载版本历史…" />}
      {versions?.map((v) => (
        <HistoryRow key={v.secretVersion} item={item} info={v} revealable={revealable} />
      ))}
    </div>
  );
}

/**
 * 单个历史版本行。租约只保存版本和到期时间，正文通过 ref 直接写入 DOM。
 * 60 秒后以及锁定、离线、切换条目或退出时立即清除。
 */
function HistoryRow({
  item,
  info,
  revealable,
}: {
  item: DecryptedItemMeta;
  info: SecretVersionInfo;
  revealable: boolean;
}) {
  const { actions, leases } = useApp();
  const toast = useUi((s) => s.toast);
  const { lease } = useLease(item.id, info.secretVersion);
  const isCurrent = info.secretVersion === item.secretVersion;
  const transient = useTransientText(`${item.id}:${info.secretVersion}`, lease !== null);
  const [emptySecret, setEmptySecret] = useState(false);

  useEffect(() => {
    if (lease === null) setEmptySecret(false);
  }, [lease]);

  const revealOld = async () => {
    try {
      const epoch = leases.epoch(item.id);
      const result = await actions.reveal(item.id, 'view', info.secretVersion);
      if (!leases.isEpochCurrent(item.id, epoch)) {
        transient.clear();
        leases.revokeVersion(item.id, info.secretVersion);
        throw new Error('状态已变化，本次读取结果已被丢弃');
      }
      if (result.value.length === 0) {
        transient.clear();
        setEmptySecret(true);
        return;
      }
      setEmptySecret(false);
      if (!transient.show(result.value)) {
        transient.clear();
        leases.revokeVersion(item.id, info.secretVersion);
        throw new Error('状态已变化，本次读取结果已被丢弃');
      }
    } catch (err) {
      toast('error', err instanceof Error ? err.message : '查看失败');
    }
  };

  return (
    <div className={styles.historyRow}>
      <span className={styles.mono}>v{info.secretVersion}</span>
      <span>{formatTime(info.createdAt)}</span>
      <span className={styles.historyBy} title={info.createdBy}>设备 {shortTechnicalId(info.createdBy)}</span>
      {!isCurrent && revealable && (
        <>
          {emptySecret && lease !== null && (
            <span className={styles.historyEmpty}>该版本未设置密码</span>
          )}
          <code ref={transient.bind} className={styles.historyValue} hidden={lease === null || emptySecret} />
          {lease !== null ? (
            <IconButton label="隐藏" onClick={() => {
              transient.clear();
              setEmptySecret(false);
              leases.revokeVersion(item.id, info.secretVersion);
            }}>
              <EyeOff size={13} />
            </IconButton>
          ) : (
            <IconButton label="查看该历史版本" onClick={() => void revealOld()}>
              <Eye size={13} />
            </IconButton>
          )}
        </>
      )}
      {isCurrent && <span className={styles.current}>当前</span>}
    </div>
  );
}

function displayActor(actorId: string, user: { id: string; displayName: string }): string {
  return actorId === user.id ? user.displayName : shortTechnicalId(actorId);
}

function shortTechnicalId(value: string): string {
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function pad(n: number): string {
  return String(n).padStart(2, '0');
}

export function CloseButton({ onClick }: { onClick: () => void }) {
  return (
    <IconButton label="关闭" onClick={onClick}>
      <X size={15} />
    </IconButton>
  );
}
