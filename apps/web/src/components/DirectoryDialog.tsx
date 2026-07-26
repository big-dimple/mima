import { useEffect, useMemo, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { FolderPlus, Save, X } from 'lucide-react';
import {
  FOLDER_PATH_MAX_DEPTH,
  FOLDER_SEGMENT_MAX_LENGTH,
  addVaultDirectory,
  materializeVaultDirectories,
  normalizeFolderPath,
  renameVaultDirectory,
  resolveVaultDirectoryPath,
} from '@mima/domain';
import { useApp, useMeta } from '../state/app-context.ts';
import { folderTreeNodeId, useUi } from '../state/ui-store.ts';
import { ActionButton } from './ActionButton.tsx';
import dialogStyles from './dialog.module.css';
import styles from './DirectoryDialog.module.css';

export type DirectoryDialogRequest =
  | { mode: 'create'; vaultId: string; parentPath: string | null }
  | { mode: 'rename'; vaultId: string; folderPath: string };

export function DirectoryDialog({
  request,
  onOpenChange,
}: {
  request: DirectoryDialogRequest | null;
  onOpenChange: (open: boolean) => void;
}) {
  const { zeroKnowledge } = useApp();
  const items = useMeta((state) => state.items);
  const storedDirectories = useMeta((state) => state.vaultDirectories);
  const selectFolder = useUi((state) => state.selectFolder);
  const expandedTreeNodeIds = useUi((state) => state.expandedTreeNodeIds);
  const expandTreeNodes = useUi((state) => state.expandTreeNodes);
  const toast = useUi((state) => state.toast);
  const [name, setName] = useState('');
  const [parentPath, setParentPath] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const directories = useMemo(() => {
    if (!request) return [];
    return materializeVaultDirectories(
      storedDirectories[request.vaultId] ?? [],
      Object.values(items)
        .filter((item) => item.vaultId === request.vaultId)
        .map((item) => item.folderPath),
    );
  }, [items, request, storedDirectories]);
  const parentOptions = directories.filter((entry) => entry.path.split('/').length < FOLDER_PATH_MAX_DEPTH);
  const sourcePath = request?.mode === 'rename' ? request.folderPath : null;
  const sourceParent = sourcePath?.split('/').slice(0, -1).join('/') ?? '';
  const normalizedName = normalizeDirectoryName(name);
  const previewPath = normalizedName
    ? [request?.mode === 'rename' ? sourceParent : parentPath, normalizedName].filter(Boolean).join('/')
    : '';

  useEffect(() => {
    if (!request) return;
    setSaving(false);
    setError(null);
    if (request.mode === 'rename') {
      setName(request.folderPath.split('/').at(-1) ?? '');
      setParentPath(request.folderPath.split('/').slice(0, -1).join('/'));
      return;
    }
    setName('');
    const requestedParent = request.parentPath ?? '';
    setParentPath(
      requestedParent && requestedParent.split('/').length < FOLDER_PATH_MAX_DEPTH
        ? requestedParent
        : '',
    );
  }, [request]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!request) return;
    if (!normalizedName || !previewPath || normalizeFolderPath(previewPath) === null) {
      setError(`目录名称不能为空、不能包含 /，且不能超过 ${FOLDER_SEGMENT_MAX_LENGTH} 个字符`);
      return;
    }
    setSaving(true);
    setError(null);
    const renamedExpandedNodeIds = request.mode === 'rename'
      ? remapExpandedFolderNodes(
          expandedTreeNodeIds,
          folderTreeNodeId(request.vaultId, request.folderPath),
          folderTreeNodeId(request.vaultId, previewPath),
        )
      : [];
    try {
      const nextDirectories = request.mode === 'create'
        ? addVaultDirectory(directories, previewPath)
        : renameVaultDirectory(directories, request.folderPath, previewPath);
      await zeroKnowledge.updateVaultDirectories(request.vaultId, nextDirectories);
      const nextSelection = request.mode === 'create'
        ? previewPath
        : resolveVaultDirectoryPath(nextDirectories, request.folderPath);
      if (renamedExpandedNodeIds.length > 0) expandTreeNodes(renamedExpandedNodeIds);
      selectFolder(nextSelection);
      onOpenChange(false);
      toast('info', request.mode === 'create' ? '目录已创建' : '目录及其中条目已统一改名');
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : '目录保存失败');
    } finally {
      setSaving(false);
    }
  };

  const renameUnchanged = request?.mode === 'rename' && previewPath === request.folderPath;
  return (
    <Dialog.Root open={request !== null} onOpenChange={(open) => {
      if (!saving) onOpenChange(open);
    }}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={dialogStyles.content}>
          <Dialog.Title className={dialogStyles.title}>
            {request?.mode === 'rename' ? '修改目录名称' : '新建目录'}
          </Dialog.Title>
          <Dialog.Description className={dialogStyles.description}>
            {request?.mode === 'rename'
              ? '改名会一次作用于这个目录和全部子目录，不需要逐条修改。'
              : '目录会在当前设备加密后同步，创建后可直接用于条目分类。'}
          </Dialog.Description>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭" disabled={saving}><X size={16} /></button>
          </Dialog.Close>
          <form className={styles.form} aria-busy={saving} onSubmit={submit}>
            {request?.mode === 'create' && (
              <label>
                上级目录
                <select value={parentPath} onChange={(event) => setParentPath(event.target.value)}>
                  <option value="">根目录</option>
                  {parentOptions.map((entry) => <option key={entry.path} value={entry.path}>{entry.path}</option>)}
                </select>
              </label>
            )}
            {request?.mode === 'rename' && sourceParent && (
              <div className={styles.parentLine}>
                <span>上级目录</span>
                <strong>{sourceParent}</strong>
              </div>
            )}
            <label>
              目录名称
              <input
                value={name}
                onChange={(event) => setName(event.target.value)}
                maxLength={FOLDER_SEGMENT_MAX_LENGTH}
                autoFocus
                onFocus={(event) => request?.mode === 'rename' && event.currentTarget.select()}
              />
            </label>
            {previewPath && <div className={styles.preview}><span>保存为</span><strong>{previewPath}</strong></div>}
            {error && <div className={styles.error} role="alert">{error}</div>}
            <div className={styles.actions}>
              <ActionButton label="取消" variant="secondary" onClick={() => onOpenChange(false)} disabled={saving} />
              <ActionButton
                label={saving ? '保存中…' : request?.mode === 'rename' ? '保存修改' : '创建目录'}
                type="submit"
                icon={request?.mode === 'rename' ? <Save size={16} /> : <FolderPlus size={16} />}
                disabled={saving || !normalizedName || Boolean(renameUnchanged)}
              />
            </div>
          </form>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function normalizeDirectoryName(value: string): string | null {
  const normalized = normalizeFolderPath(value);
  return normalized && !normalized.includes('/') ? normalized : null;
}

function remapExpandedFolderNodes(
  nodeIds: ReadonlySet<string>,
  sourcePrefix: string,
  targetPrefix: string,
): string[] {
  return [...nodeIds].flatMap((nodeId) => {
    if (nodeId === sourcePrefix) return [targetPrefix];
    if (nodeId.startsWith(`${sourcePrefix}/`)) {
      return [`${targetPrefix}${nodeId.slice(sourcePrefix.length)}`];
    }
    return [];
  });
}
