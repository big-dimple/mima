import { useEffect, useMemo, useRef, useState } from 'react';
import { BriefcaseBusiness, ChevronDown, ChevronsUp, Folder, FolderOpen, FolderPlus, Inbox, Users, Plus, ScrollText, Star, Layers, User, Pencil, Trash2 } from 'lucide-react';
import {
  materializeVaultDirectories,
  removeVaultDirectory,
  countVaultDirectorySubtreeItems,
  vaultDirectoryDescendantPaths,
  resolveEffectiveRole,
  canManageMembers,
  canReadAudit,
  type VaultDirectoryEntry,
} from '@mima/domain';
import type { MembershipRole, Vault } from '@mima/contracts';
import type { DecryptedItemMeta } from '@mima/client-core';
import { useApp, useMeta } from '../state/app-context.ts';
import { folderTreeNodeId, useUi } from '../state/ui-store.ts';
import { useFolderDrop } from '../hooks/useFolderDrop.ts';
import { useDrag } from '../state/drag-store.ts';
import { IconButton } from './IconButton.tsx';
import { CreateVaultDialog } from './CreateVaultDialog.tsx';
import { RenameVaultDialog } from './RenameVaultDialog.tsx';
import { DeleteVaultDialog } from './DeleteVaultDialog.tsx';
import { DirectoryDialog, type DirectoryDialogRequest } from './DirectoryDialog.tsx';
import styles from './VaultNav.module.css';

const ROLE_LABEL: Record<MembershipRole, string> = {
  owner: '拥有者',
  editor: '编辑',
  viewer: '查看',
  auditor: '审计',
};

const VAULT_SECTION_STATE_KEY = 'mima:vault-sections:v1';
const vaultNodeId = (vaultId: string) => `vault:${vaultId}`;
const projectSectionNodeId = (vaultId: string) => `projects:${vaultId}`;
const directorySectionNodeId = (vaultId: string) => `directories:${vaultId}`;
const vaultRowTreeId = (vaultId: string) => `vault-row:${vaultId}`;
const projectSectionTreeId = (vaultId: string) => `project-section:${vaultId}`;
const directorySectionTreeId = (vaultId: string) => `directory-section:${vaultId}`;
const folderRowTreeId = (vaultId: string, path: string) => `folder-row:${vaultId}:${path}`;

export function VaultNav() {
  const user = useMeta((s) => s.user)!;
  const vaults = useMeta((s) => s.vaults);
  const memberships = useMeta((s) => s.memberships);
  const items = useMeta((s) => s.items);
  const vaultDirectories = useMeta((s) => s.vaultDirectories);
  const connection = useMeta((s) => s.connection);
  const { zeroKnowledge } = useApp();
  const ui = useUi();
  const [creating, setCreating] = useState(false);
  const [creatingProject, setCreatingProject] = useState<Vault | null>(null);
  const [renaming, setRenaming] = useState<Vault | null>(null);
  const [deleting, setDeleting] = useState<Vault | null>(null);
  const [directoryDialog, setDirectoryDialog] = useState<DirectoryDialogRequest | null>(null);
  const [sectionVisibility, setSectionVisibility] = useState(readVaultSectionVisibility);
  const navRef = useRef<HTMLElement>(null);
  const typeaheadRef = useRef({ value: '', at: 0 });

  useEffect(() => {
    try {
      localStorage.setItem(VAULT_SECTION_STATE_KEY, JSON.stringify(sectionVisibility));
    } catch {
      // Private browsing may disable localStorage; section controls still work for this page.
    }
  }, [sectionVisibility]);

  const personal = Object.values(vaults).filter((v) => v.kind === 'personal');
  const teams = Object.values(vaults)
    .filter((v) => v.kind === 'team')
    .sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'));
  const teamById = new Map(teams.map((vault) => [vault.id, vault]));
  const projectsByParent = new Map<string, Vault[]>();
  const topLevelTeams: Vault[] = [];
  for (const vault of teams) {
    const parentId = vault.projectContext?.kind === 'project'
      ? vault.projectContext.visibleParentVaultId
      : null;
    if (!parentId || !teamById.has(parentId)) {
      topLevelTeams.push(vault);
      continue;
    }
    const projects = projectsByParent.get(parentId) ?? [];
    projects.push(vault);
    projectsByParent.set(parentId, projects);
  }
  const folderItems = useMemo(
    () => Object.values(items).filter((item) => item.vaultId === ui.selectedVaultId),
    [items, ui.selectedVaultId],
  );

  const roleOf = (vault: Vault): MembershipRole | null =>
    vault.kind === 'personal'
      ? 'owner'
      : resolveEffectiveRole(memberships[vault.id] ?? [], { userId: user.id, groups: user.groups });

  const isExpanded = (id: string) => ui.expandedTreeNodeIds.has(id);
  const revealVault = (vaultId: string) => {
    const vault = vaults[vaultId];
    const ids = [vaultNodeId(vaultId), directorySectionNodeId(vaultId)];
    const parentId = vault?.projectContext?.kind === 'project'
      ? vault.projectContext.visibleParentVaultId
      : null;
    if (parentId) ids.push(vaultNodeId(parentId), projectSectionNodeId(parentId));
    ui.expandTreeNodes(ids);
  };

  const selectOrToggleVault = (vaultId: string) => {
    if (ui.selectedVaultId === vaultId) {
      ui.toggleTreeNode(vaultNodeId(vaultId));
      return;
    }
    revealVault(vaultId);
    ui.selectVault(vaultId);
  };

  useEffect(() => {
    if (!vaults[ui.selectedVaultId]) return;
    revealVault(ui.selectedVaultId);
  }, [ui.selectedVaultId]);

  useEffect(() => {
    if (!vaults[ui.selectedVaultId] || !ui.selectedFolderPath) return;
    const parts = ui.selectedFolderPath.split('/');
    const ids = [directorySectionNodeId(ui.selectedVaultId)];
    for (let index = 1; index < parts.length; index += 1) {
      ids.push(folderTreeNodeId(ui.selectedVaultId, parts.slice(0, index).join('/')));
    }
    ui.expandTreeNodes(ids);
  }, [ui.selectedFolderPath, ui.selectedVaultId]);

  useEffect(() => {
    const validIds = new Set<string>();
    for (const vault of Object.values(vaults)) {
      validIds.add(vaultNodeId(vault.id));
      validIds.add(directorySectionNodeId(vault.id));
      if ((projectsByParent.get(vault.id) ?? []).length > 0) validIds.add(projectSectionNodeId(vault.id));
      const paths = materializeVaultDirectories(
        vaultDirectories[vault.id] ?? [],
        Object.values(items).filter((item) => item.vaultId === vault.id).map((item) => item.folderPath),
      ).map((entry) => entry.path);
      for (const path of paths) {
        const parts = path.split('/');
        for (let index = 1; index < parts.length; index += 1) {
          validIds.add(folderTreeNodeId(vault.id, parts.slice(0, index).join('/')));
        }
      }
    }
    ui.pruneTreeNodes(validIds);
  }, [items, vaultDirectories, vaults]);

  useEffect(() => {
    const rows = treeRows(navRef.current);
    if (rows.length === 0) return;
    const active = document.activeElement instanceof HTMLElement && rows.includes(document.activeElement)
      ? document.activeElement
      : rows.find((row) => row.tabIndex === 0) ?? rows[0]!;
    for (const row of rows) row.tabIndex = row === active ? 0 : -1;
  });

  const handleTreeKeyDown = (event: React.KeyboardEvent<HTMLElement>) => {
    const target = event.target;
    if (!(target instanceof HTMLElement) || target.dataset.treeRow !== 'true') return;
    const rows = treeRows(navRef.current);
    const index = rows.indexOf(target);
    if (index < 0) return;
    let destination: HTMLElement | null = null;
    if (event.key === 'ArrowDown') destination = rows[Math.min(rows.length - 1, index + 1)] ?? null;
    else if (event.key === 'ArrowUp') destination = rows[Math.max(0, index - 1)] ?? null;
    else if (event.key === 'Home') destination = rows[0] ?? null;
    else if (event.key === 'End') destination = rows.at(-1) ?? null;
    else if (event.key === 'ArrowRight') {
      if (target.dataset.treeExpanded === 'false') {
        findTreeDisclosure(navRef.current, target.dataset.treeId)?.click();
      } else if (target.dataset.treeExpanded === 'true') {
        destination = rows.find((row) => row.dataset.treeParentId === target.dataset.treeId) ?? null;
      }
    } else if (event.key === 'ArrowLeft') {
      if (target.dataset.treeExpanded === 'true') {
        findTreeDisclosure(navRef.current, target.dataset.treeId)?.click();
      } else {
        destination = rows.find((row) => row.dataset.treeId === target.dataset.treeParentId) ?? null;
      }
    } else if (event.key.length === 1 && !event.ctrlKey && !event.metaKey && !event.altKey) {
      const now = Date.now();
      const prefix = now - typeaheadRef.current.at > 700
        ? event.key
        : `${typeaheadRef.current.value}${event.key}`;
      typeaheadRef.current = { value: prefix.toLocaleLowerCase(), at: now };
      destination = [...rows.slice(index + 1), ...rows.slice(0, index + 1)]
        .find((row) => row.dataset.treeLabel?.startsWith(typeaheadRef.current.value)) ?? null;
    } else {
      return;
    }
    event.preventDefault();
    if (destination) focusTreeRow(rows, destination);
  };

  // 删除目录：只删空子树；非空明确拒绝，空目录二次确认，成功后选中仍存在的父目录。
  const deleteDirectory = async (vaultId: string, folderPath: string) => {
    const directories = vaultDirectories[vaultId] ?? [];
    const itemFolderPaths = Object.values(items)
      .filter((item) => item.vaultId === vaultId)
      .map((item) => item.folderPath);
    const itemCount = countVaultDirectorySubtreeItems(directories, folderPath, itemFolderPaths);
    if (itemCount > 0) {
      // 非空：不删除、不搬迁、不静默失败，明确提示先移动条目。
      ui.toast('warn', `“${folderPath}”及子目录中还有 ${itemCount} 个条目，请先移动条目后再删除目录`);
      return;
    }
    const descendants = vaultDirectoryDescendantPaths(directories, folderPath, itemFolderPaths);
    const confirmed = await useUi.getState().requestConfirm({
      title: '删除目录',
      body: descendants.length > 0
        ? `确定删除“${folderPath}”及其 ${descendants.length} 个空子目录？不会删除任何条目，也不会改变成员权限。`
        : `确定删除“${folderPath}”？不会删除任何条目，也不会改变成员权限。`,
      confirmText: '删除',
      cancelText: '取消',
      danger: true,
    });
    if (!confirmed) return;
    try {
      const next = removeVaultDirectory(directories, folderPath, itemFolderPaths);
      await zeroKnowledge.updateVaultDirectories(vaultId, next);
      // 成功后选中最近仍存在的父目录；删除顶层目录后回到“全部”。
      const parent = folderPath.split('/').slice(0, -1).join('/');
      ui.selectFolder(parent || null);
      ui.toast('info', '目录已删除，条目未受影响');
    } catch (error) {
      ui.toast('error', error instanceof Error ? error.message : '目录删除失败');
    }
  };

  const navItem = (
    id: string,
    label: string,
    icon: React.ReactNode,
    extra?: React.ReactNode,
    options: {
      stackActions?: boolean;
      expandable?: boolean;
      expanded?: boolean;
      onClick?: () => void;
      onToggle?: () => void;
      parentTreeId?: string;
    } = {},
  ) => {
    const treeId = vaultRowTreeId(id);
    return (
      <div
        key={id}
        className={[
          styles.item,
          options.stackActions ? styles.itemStacked : '',
          ui.selectedVaultId === id ? styles.selected : '',
        ].join(' ')}
      >
        {options.expandable ? (
          <button
            type="button"
            className={styles.vaultDisclosure}
            aria-label={options.expanded ? `折叠${label}` : `展开${label}`}
            aria-expanded={Boolean(options.expanded)}
            data-tree-disclosure={treeId}
            tabIndex={-1}
            onClick={options.onToggle}
          >
            <ChevronDown
              className={options.expanded ? undefined : styles.vaultChevronCollapsed}
              size={14}
              aria-hidden
            />
          </button>
        ) : <span className={styles.disclosureSpacer} aria-hidden />}
        <button
          className={styles.itemMain}
          aria-label={label}
          title={label}
          aria-current={ui.selectedVaultId === id ? 'page' : undefined}
          data-tree-row="true"
          data-tree-id={treeId}
          data-tree-parent-id={options.parentTreeId}
          data-tree-label={label.toLocaleLowerCase()}
          data-tree-expanded={options.expandable ? String(Boolean(options.expanded)) : undefined}
          onClick={options.onClick ?? (() => ui.selectVault(id))}
        >
          {icon}
          <span className={styles.itemLabel}>{label}</span>
        </button>
        {extra}
      </div>
    );
  };

  const teamVaultBlock = (vault: Vault, nested = false, parentTreeId = 'section:team') => {
    const role = roleOf(vault);
    const projects = nested ? [] : (projectsByParent.get(vault.id) ?? []);
    const isProject = vault.projectContext?.kind === 'project';
    const vaultExpanded = isExpanded(vaultNodeId(vault.id));
    const projectsExpanded = isExpanded(projectSectionNodeId(vault.id));
    return (
      <div className={[styles.vaultBlock, nested ? styles.projectVault : ''].join(' ')} key={vault.id}>
        {navItem(
          vault.id,
          vault.name,
          isProject
            ? <BriefcaseBusiness size={15} aria-hidden />
            : <Users size={15} aria-hidden />,
          <span className={styles.itemActions}>
            {isProject && <span className={styles.projectBadge}>项目</span>}
            {role && <span className={styles.roleBadge}>{ROLE_LABEL[role]}</span>}
            {role === 'owner' && (
              <IconButton label="编辑团队密码库" onClick={() => setRenaming(vault)}>
                <Pencil size={13} />
              </IconButton>
            )}
            {canReadAudit(role, user.isPlatformAdmin) && (
              <IconButton label="查看审计日志" onClick={() => ui.openAudit(vault.id)}>
                <ScrollText size={13} />
              </IconButton>
            )}
            {role && (
              <IconButton
                label={canManageMembers(role) ? '管理成员' : '查看成员和所有权转移'}
                onClick={() => ui.openMembers(vault.id)}
                tour={canManageMembers(role) ? 'members' : undefined}
              >
                <Users size={13} />
              </IconButton>
            )}
            {role === 'owner' && (
              <IconButton
                label="删除团队密码库"
                danger
                disabled={connection !== 'online'}
                onClick={() => setDeleting(vault)}
                ariaHaspopup="dialog"
              >
                <Trash2 size={13} />
              </IconButton>
            )}
          </span>,
          {
            stackActions: true,
            expandable: ui.selectedVaultId === vault.id || projects.length > 0,
            expanded: vaultExpanded,
            onClick: () => selectOrToggleVault(vault.id),
            onToggle: () => ui.toggleTreeNode(vaultNodeId(vault.id)),
            parentTreeId,
          },
        )}
        {ui.selectedVaultId === vault.id && vaultExpanded && (
          <VaultFolderTree
            items={folderItems}
            directories={vaultDirectories[vault.id] ?? []}
            selectedPath={ui.selectedFolderPath}
            onSelect={ui.selectFolder}
            canManage={role === 'owner'}
            online={connection === 'online'}
            vaultId={vault.id}
            onCreate={() => setDirectoryDialog({
              mode: 'create',
              vaultId: vault.id,
              parentPath: ui.selectedFolderPath || null,
            })}
            onRename={(folderPath) => setDirectoryDialog({ mode: 'rename', vaultId: vault.id, folderPath })}
            onDelete={(folderPath) => void deleteDirectory(vault.id, folderPath)}
            expanded={isExpanded(directorySectionNodeId(vault.id))}
            expandedNodeIds={ui.expandedTreeNodeIds}
            onToggleNode={ui.toggleTreeNode}
            parentTreeId={vaultRowTreeId(vault.id)}
          />
        )}
        {vaultExpanded && projects.length > 0 && (
          <div className={styles.projectTree} role="group" aria-label={`${vault.name}的项目`}>
            <div className={styles.projectTitle}>
              <button
                type="button"
                className={styles.projectToggle}
                aria-label={projectsExpanded ? `折叠${vault.name}的项目` : `展开${vault.name}的项目`}
                aria-expanded={projectsExpanded}
                data-tree-row="true"
                data-tree-id={projectSectionTreeId(vault.id)}
                data-tree-disclosure={projectSectionTreeId(vault.id)}
                data-tree-parent-id={vaultRowTreeId(vault.id)}
                data-tree-label="项目"
                data-tree-expanded={String(projectsExpanded)}
                onClick={() => ui.toggleTreeNode(projectSectionNodeId(vault.id))}
              >
                <ChevronDown className={projectsExpanded ? undefined : styles.sectionChevronCollapsed} size={14} aria-hidden />
                <span>项目</span>
                <span className={styles.projectCount}>{projects.length}</span>
              </button>
              {role === 'owner' && (
                <IconButton
                  label={`在${vault.name}下新建项目`}
                  onClick={() => setCreatingProject(vault)}
                  disabled={connection !== 'online'}
                >
                  <Plus size={14} />
                </IconButton>
              )}
            </div>
            {projectsExpanded && <div className={styles.projectList} role="group">
              {projects.map((project) => teamVaultBlock(project, true, projectSectionTreeId(vault.id)))}
            </div>}
          </div>
        )}
      </div>
    );
  };

  return (
    <nav
      ref={navRef}
      className={styles.nav}
      aria-label="库导航"
      data-tour="vault-nav"
      onKeyDown={handleTreeKeyDown}
    >
      <div className={styles.navTools}>
        <IconButton
          label="全部收起"
          disabled={!sectionVisibility.personal && !sectionVisibility.team && ui.expandedTreeNodeIds.size === 0}
          onClick={() => {
            setSectionVisibility({ personal: false, team: false });
            ui.collapseAllTreeNodes();
          }}
        >
          <ChevronsUp size={15} />
        </IconButton>
      </div>
      <div className={styles.section}>
        {navItem('all', '全部条目', <Layers size={15} aria-hidden />)}
        {navItem('favorites', '收藏', <Star size={15} aria-hidden />)}
      </div>

      <div className={styles.sectionTitle}>
        <button
          className={styles.sectionToggle}
          type="button"
          aria-expanded={sectionVisibility.personal}
          aria-controls="personal-vaults"
          aria-label={sectionVisibility.personal ? '折叠个人库' : '展开个人库'}
          data-tree-row="true"
          data-tree-id="section:personal"
          data-tree-disclosure="section:personal"
          data-tree-label="个人"
          data-tree-expanded={String(sectionVisibility.personal)}
          onClick={() => setSectionVisibility((current) => ({ ...current, personal: !current.personal }))}
        >
          <ChevronDown
            className={sectionVisibility.personal ? undefined : styles.sectionChevronCollapsed}
            size={14}
            aria-hidden
          />
          <span>个人</span>
        </button>
      </div>
      {sectionVisibility.personal && <div className={styles.section} id="personal-vaults">
        {personal.map((v) => (
          <div className={styles.vaultBlock} key={v.id}>
            {navItem(
              v.id,
              v.name,
              <User size={15} aria-hidden />,
              <span className={styles.itemActions}>
                <IconButton label="修改密码库名称" onClick={() => setRenaming(v)} tour="rename-vault">
                  <Pencil size={13} />
                </IconButton>
              </span>,
              {
                expandable: ui.selectedVaultId === v.id,
                expanded: isExpanded(vaultNodeId(v.id)),
                onClick: () => selectOrToggleVault(v.id),
                onToggle: () => ui.toggleTreeNode(vaultNodeId(v.id)),
                parentTreeId: 'section:personal',
              },
            )}
            {ui.selectedVaultId === v.id && isExpanded(vaultNodeId(v.id)) && (
              <VaultFolderTree
                items={folderItems}
                directories={vaultDirectories[v.id] ?? []}
                selectedPath={ui.selectedFolderPath}
                onSelect={ui.selectFolder}
                canManage
                online={connection === 'online'}
                vaultId={v.id}
                onCreate={() => setDirectoryDialog({
                  mode: 'create',
                  vaultId: v.id,
                  parentPath: ui.selectedFolderPath || null,
                })}
                onRename={(folderPath) => setDirectoryDialog({ mode: 'rename', vaultId: v.id, folderPath })}
                onDelete={(folderPath) => void deleteDirectory(v.id, folderPath)}
                expanded={isExpanded(directorySectionNodeId(v.id))}
                expandedNodeIds={ui.expandedTreeNodeIds}
                onToggleNode={ui.toggleTreeNode}
                parentTreeId={vaultRowTreeId(v.id)}
              />
            )}
          </div>
        ))}
      </div>}

      <div className={styles.sectionTitle}>
        <button
          className={styles.sectionToggle}
          type="button"
          aria-expanded={sectionVisibility.team}
          aria-controls="team-vaults"
          aria-label={sectionVisibility.team ? '折叠团队库' : '展开团队库'}
          data-tree-row="true"
          data-tree-id="section:team"
          data-tree-disclosure="section:team"
          data-tree-label="团队"
          data-tree-expanded={String(sectionVisibility.team)}
          onClick={() => setSectionVisibility((current) => ({ ...current, team: !current.team }))}
        >
          <ChevronDown
            className={sectionVisibility.team ? undefined : styles.sectionChevronCollapsed}
            size={14}
            aria-hidden
          />
          <span>团队</span>
        </button>
        <IconButton label="新建团队库" onClick={() => setCreating(true)} disabled={connection !== 'online'} tour="new-team">
          <Plus size={14} />
        </IconButton>
      </div>
      {sectionVisibility.team && <div className={styles.section} id="team-vaults">
        {teams.length === 0 && (
          <div className={styles.empty}>暂无团队库</div>
        )}
        {topLevelTeams.map((vault) => teamVaultBlock(vault))}
      </div>}
      <CreateVaultDialog open={creating} onOpenChange={setCreating} />
      <CreateVaultDialog
        open={creatingProject !== null}
        parentVault={creatingProject}
        onOpenChange={(open) => {
          if (!open) setCreatingProject(null);
        }}
      />
      <RenameVaultDialog vault={renaming} onOpenChange={(open) => {
        if (!open) setRenaming(null);
      }} onCreateProject={setCreatingProject} />
      <DeleteVaultDialog vault={deleting} onOpenChange={(open) => {
        if (!open) setDeleting(null);
      }} />
      <DirectoryDialog request={directoryDialog} onOpenChange={(open) => {
        if (!open) setDirectoryDialog(null);
      }} />
      {user.isPlatformAdmin && (
        <div className={styles.adminNote}>
          系统管理员可以创建团队密码库和查看操作记录；没有被授权时不能查看库内密码或管理成员。
        </div>
      )}
    </nav>
  );
}

function treeRows(root: HTMLElement | null): HTMLElement[] {
  return root ? Array.from(root.querySelectorAll<HTMLElement>('[data-tree-row="true"]')) : [];
}

function findTreeDisclosure(root: HTMLElement | null, treeId: string | undefined): HTMLButtonElement | null {
  if (!root || !treeId) return null;
  return Array.from(root.querySelectorAll<HTMLButtonElement>('[data-tree-disclosure]'))
    .find((button) => button.dataset.treeDisclosure === treeId) ?? null;
}

function focusTreeRow(rows: HTMLElement[], destination: HTMLElement): void {
  for (const row of rows) row.tabIndex = row === destination ? 0 : -1;
  destination.focus({ preventScroll: true });
  if (typeof destination.scrollIntoView === 'function') {
    destination.scrollIntoView({ block: 'nearest' });
  }
}

function readVaultSectionVisibility(): { personal: boolean; team: boolean } {
  if (typeof window === 'undefined') return { personal: true, team: true };
  try {
    const parsed = JSON.parse(localStorage.getItem(VAULT_SECTION_STATE_KEY) ?? '{}') as {
      personal?: unknown;
      team?: unknown;
    };
    return {
      personal: typeof parsed.personal === 'boolean' ? parsed.personal : true,
      team: typeof parsed.team === 'boolean' ? parsed.team : true,
    };
  } catch {
    return { personal: true, team: true };
  }
}

interface FolderNode {
  name: string;
  path: string;
  count: number;
  children: FolderNode[];
}

function VaultFolderTree({
  items,
  directories,
  selectedPath,
  onSelect,
  canManage,
  online,
  onCreate,
  onRename,
  onDelete,
  vaultId,
  expanded,
  expandedNodeIds,
  onToggleNode,
  parentTreeId,
}: {
  items: DecryptedItemMeta[];
  directories: VaultDirectoryEntry[];
  selectedPath: string | null;
  onSelect: (path: string | null) => void;
  canManage: boolean;
  online: boolean;
  onCreate: () => void;
  onRename: (path: string) => void;
  onDelete: (path: string) => void;
  vaultId: string;
  expanded: boolean;
  expandedNodeIds: ReadonlySet<string>;
  onToggleNode: (id: string) => void;
  parentTreeId: string;
}) {
  const tree = useMemo(() => buildFolderTree(items, directories), [items, directories]);
  const unclassified = items.filter((item) => !item.folderPath).length;
  const draggingToThisVault = useDrag((state) => Boolean(
    state.draggingItemId && state.sourceVaultId === vaultId
  ));
  const showUnclassified = unclassified > 0 || draggingToThisVault;
  useEffect(() => {
    if (unclassified === 0 && selectedPath === '') onSelect(null);
  }, [onSelect, selectedPath, unclassified]);
  // 只有选中真实目录（非“全部”/“未分类”）才允许改名或删除。
  const hasSelectedDirectory = Boolean(selectedPath);
  const deleteDirectoryLabel = !online
    ? '联网后可删除目录'
    : hasSelectedDirectory
      ? '删除当前目录'
      : '先选择要删除的目录';

  return (
    <div className={styles.folderTree} aria-label="目录导航">
      <div className={styles.folderTitle}>
        <button
          type="button"
          className={styles.folderTitleToggle}
          aria-label={expanded ? '折叠目录' : '展开目录'}
          aria-expanded={expanded}
          data-tree-row="true"
          data-tree-id={`directory-section:${vaultId}`}
          data-tree-disclosure={`directory-section:${vaultId}`}
          data-tree-parent-id={parentTreeId}
          data-tree-label="目录"
          data-tree-expanded={String(expanded)}
          onClick={() => onToggleNode(directorySectionNodeId(vaultId))}
        >
          <ChevronDown className={expanded ? undefined : styles.sectionChevronCollapsed} size={14} aria-hidden />
          <span>目录</span>
        </button>
        {canManage && (
          <span className={styles.folderTools} role="group" aria-label="目录操作">
            <IconButton label="新建目录" onClick={onCreate} disabled={!online}>
              <FolderPlus size={15} />
            </IconButton>
            <IconButton
              label="修改当前目录"
              onClick={() => selectedPath && onRename(selectedPath)}
              disabled={!online || !hasSelectedDirectory}
            >
              <Pencil size={14} />
            </IconButton>
            <IconButton
              label={deleteDirectoryLabel}
              onClick={() => selectedPath && onDelete(selectedPath)}
              disabled={!online || !hasSelectedDirectory}
              danger
            >
              <Trash2 size={14} />
            </IconButton>
          </span>
        )}
      </div>
      {expanded && <div className={styles.folderList} role="group">
        <FolderRow
          label="全部"
          count={items.length}
          selected={selectedPath === null}
          icon={<FolderOpen size={14} aria-hidden />}
          onClick={() => onSelect(null)}
          parentTreeId={directorySectionTreeId(vaultId)}
        />
        {showUnclassified && (
          <FolderRow
            label="未分类"
            count={unclassified}
            selected={selectedPath === ''}
            icon={<Inbox size={14} aria-hidden />}
            onClick={() => onSelect('')}
            dropPath=""
            vaultId={vaultId}
            parentTreeId={directorySectionTreeId(vaultId)}
          />
        )}
        {tree.map((node) => (
          <FolderBranch
            key={node.path}
            node={node}
            depth={0}
            selectedPath={selectedPath}
            onSelect={onSelect}
            vaultId={vaultId}
            expandedNodeIds={expandedNodeIds}
            onToggleNode={onToggleNode}
            parentTreeId={directorySectionTreeId(vaultId)}
          />
        ))}
      </div>}
    </div>
  );
}

function FolderBranch({
  node,
  depth,
  selectedPath,
  onSelect,
  vaultId,
  expandedNodeIds,
  onToggleNode,
  parentTreeId,
}: {
  node: FolderNode;
  depth: number;
  selectedPath: string | null;
  onSelect: (path: string | null) => void;
  vaultId: string;
  expandedNodeIds: ReadonlySet<string>;
  onToggleNode: (id: string) => void;
  parentTreeId: string;
}) {
  const expandable = node.children.length > 0;
  const expanded = expandable && expandedNodeIds.has(folderTreeNodeId(vaultId, node.path));
  return (
    <div className={styles.folderBranch} role="treeitem" aria-expanded={expandable ? expanded : undefined}>
      <FolderRow
        label={node.name}
        accessibleLabel={`目录：${node.path}`}
        count={node.count}
        depth={depth}
        selected={selectedPath === node.path}
        icon={<Folder size={14} aria-hidden />}
        onClick={() => onSelect(node.path)}
        dropPath={node.path}
        vaultId={vaultId}
        expandable={expandable}
        expanded={expanded}
        onToggle={() => onToggleNode(folderTreeNodeId(vaultId, node.path))}
        parentTreeId={parentTreeId}
      />
      {expanded && <div className={styles.folderChildren} role="group">
        {node.children.map((child) => (
        <FolderBranch
          key={child.path}
          node={child}
          depth={depth + 1}
          selectedPath={selectedPath}
          onSelect={onSelect}
          vaultId={vaultId}
          expandedNodeIds={expandedNodeIds}
          onToggleNode={onToggleNode}
          parentTreeId={folderRowTreeId(vaultId, node.path)}
        />
        ))}
      </div>}
    </div>
  );
}

function FolderRow({
  label,
  accessibleLabel,
  count,
  depth = 0,
  selected,
  icon,
  onClick,
  dropPath,
  vaultId,
  expandable = false,
  expanded = false,
  onToggle,
  parentTreeId,
}: {
  label: string;
  accessibleLabel?: string;
  count: number;
  depth?: number;
  selected: boolean;
  icon: React.ReactNode;
  onClick: () => void;
  /** undefined=非拖拽目标（“全部”）；''=未分类（folderPath:null）；其他=真实目录路径。 */
  dropPath?: string;
  vaultId?: string | null;
  expandable?: boolean;
  expanded?: boolean;
  onToggle?: () => void;
  parentTreeId: string;
}) {
  const isDropTarget = dropPath !== undefined;
  const { isOver, canDrop, dropProps } = useFolderDrop(
    isDropTarget ? (vaultId ?? null) : null,
    dropPath ?? '',
  );
  const treeId = folderRowTreeId(vaultId ?? 'global', dropPath ?? label);
  return (
    <div
      className={[
        styles.folderRow,
        selected ? styles.folderSelected : '',
        canDrop ? styles.folderDropReady : '',
        isOver ? styles.folderDropTarget : '',
      ].join(' ')}
      style={{ paddingInlineStart: `${7 + depth * 14}px` }}
      data-drop-state={isOver ? 'over' : canDrop ? 'ready' : undefined}
      {...(isDropTarget ? dropProps : {})}
    >
      {expandable ? (
        <button
          type="button"
          className={styles.folderDisclosure}
          aria-label={expanded ? `折叠${accessibleLabel ?? `目录：${label}`}` : `展开${accessibleLabel ?? `目录：${label}`}`}
          aria-expanded={expanded}
          data-tree-disclosure={treeId}
          tabIndex={-1}
          onClick={onToggle}
        >
          <ChevronDown className={expanded ? undefined : styles.vaultChevronCollapsed} size={13} aria-hidden />
        </button>
      ) : <span className={styles.folderDisclosureSpacer} aria-hidden />}
      <button
        type="button"
        className={styles.folderMain}
        aria-label={accessibleLabel ?? `目录：${label}`}
        aria-current={selected ? 'page' : undefined}
        data-drop-state={isOver ? 'over' : canDrop ? 'ready' : undefined}
        data-tree-row="true"
        data-tree-id={treeId}
        data-tree-parent-id={parentTreeId}
        data-tree-label={label.toLocaleLowerCase()}
        data-tree-expanded={expandable ? String(expanded) : undefined}
        onClick={onClick}
      >
        {icon}
        <span className={styles.folderLabel}>{label}</span>
        <span className={styles.folderCount}>{count}</span>
      </button>
    </div>
  );
}

function buildFolderTree(items: DecryptedItemMeta[], directories: VaultDirectoryEntry[]): FolderNode[] {
  interface MutableFolderNode {
    name: string;
    path: string;
    count: number;
    children: Map<string, MutableFolderNode>;
  }

  const roots = new Map<string, MutableFolderNode>();
  const paths = materializeVaultDirectories(directories, items.map((item) => item.folderPath))
    .map((entry) => entry.path);
  for (const folderPath of paths) {
    let level = roots;
    let parentPath = '';
    for (const name of folderPath.split('/')) {
      const path = parentPath ? `${parentPath}/${name}` : name;
      const existing = level.get(name);
      const node = existing ?? { name, path, count: 0, children: new Map() };
      if (!existing) level.set(name, node);
      level = node.children;
      parentPath = path;
    }
  }
  for (const item of items) {
    if (!item.folderPath) continue;
    let level = roots;
    for (const name of item.folderPath.split('/')) {
      const node = level.get(name);
      if (!node) break;
      node.count += 1;
      level = node.children;
    }
  }
  const finalize = (nodes: Map<string, MutableFolderNode>): FolderNode[] => Array.from(nodes.values())
    .map((node) => ({
      name: node.name,
      path: node.path,
      count: node.count,
      children: finalize(node.children),
    }))
    .sort((left, right) => left.name.localeCompare(right.name, 'zh-CN'));
  return finalize(roots);
}
