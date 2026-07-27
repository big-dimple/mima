import { KeyRound, Layers3, NotebookPen, UserRound } from 'lucide-react';
import type { ItemKind } from '@mima/contracts';
import { getItemPresentation } from '@mima/domain';
import styles from './ItemKindMark.module.css';

export type ItemKindFilter = ItemKind | 'all';

const KIND_ICON = {
  all: Layers3,
  login: UserRound,
  api_token: KeyRound,
  secure_note: NotebookPen,
} as const;

export function ItemKindMark({ kind, compact = false }: { kind: ItemKindFilter; compact?: boolean }) {
  const Icon = KIND_ICON[kind];
  return (
    <span
      className={[styles.mark, styles[kind], compact ? styles.compact : ''].join(' ')}
      aria-hidden
      data-kind={kind}
    >
      <Icon size={compact ? 13 : 15} strokeWidth={2} />
    </span>
  );
}

export function ItemKindBadge({ kind }: { kind: ItemKind }) {
  return (
    <span className={[styles.badge, styles[`${kind}Badge`]].join(' ')}>
      <ItemKindMark kind={kind} compact />
      <span>{getItemPresentation(kind).kindLabel}</span>
    </span>
  );
}
