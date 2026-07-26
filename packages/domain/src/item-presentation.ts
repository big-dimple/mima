import type { ItemKind } from '@mima/contracts';

export const ITEM_DESCRIPTION_MAX_LENGTH = 1000;

export interface ItemPresentation {
  kindLabel: string;
  auxiliaryLabel: string | null;
  auxiliaryHint: string | null;
  secretLabel: string;
  copyAuxiliaryLabel: string | null;
  copySecretLabel: string;
}

const ITEM_PRESENTATION: Record<ItemKind, ItemPresentation> = {
  login: {
    kindLabel: '账号密码',
    auxiliaryLabel: '账号',
    auxiliaryHint: '用户名 / 登录账号（可选）',
    secretLabel: '密码',
    copyAuxiliaryLabel: '复制账号',
    copySecretLabel: '复制密码',
  },
  api_token: {
    kindLabel: 'API 凭证',
    auxiliaryLabel: '凭证标识',
    auxiliaryHint: 'SecretId / AccessKey ID / Client ID / 账号',
    secretLabel: '密钥 / Token',
    copyAuxiliaryLabel: '复制凭证标识',
    copySecretLabel: '复制密钥 / Token',
  },
  secure_note: {
    kindLabel: '安全备注',
    auxiliaryLabel: null,
    auxiliaryHint: null,
    secretLabel: '备注正文',
    copyAuxiliaryLabel: null,
    copySecretLabel: '复制备注',
  },
};

export function getItemPresentation(kind: ItemKind): ItemPresentation {
  return ITEM_PRESENTATION[kind];
}

export function getVisibleItemAuxiliary(kind: ItemKind, value: string | null): string | null {
  if (kind === 'secure_note') return null;
  const trimmed = value?.trim() ?? '';
  return trimmed.length > 0 ? trimmed : null;
}
