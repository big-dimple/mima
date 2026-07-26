import { useEffect, useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import type { LegacyKeyRetirementResponse } from '@mima/contracts';
import { useApp } from '../state/app-context.ts';
import styles from './LegacyKeyRetirementBanner.module.css';

type RetirementState =
  | { status: 'loading' }
  | { status: 'error' }
  | { status: 'ready'; value: LegacyKeyRetirementResponse };

export function LegacyKeyRetirementBanner() {
  const { api } = useApp();
  const [state, setState] = useState<RetirementState>({ status: 'loading' });

  useEffect(() => {
    let active = true;
    const load = () => {
      void api.legacyKeyRetirementStatus().then(
        (value) => {
          if (active) setState({ status: 'ready', value });
        },
        () => {
          if (active) setState({ status: 'error' });
        },
      );
    };
    load();
    window.addEventListener('mima:legacy-retirement-updated', load);
    return () => {
      active = false;
      window.removeEventListener('mima:legacy-retirement-updated', load);
    };
  }, [api]);

  if (state.status === 'loading') return null;
  if (state.status === 'error') {
    return (
      <div className={[styles.banner, styles.danger].join(' ')} role="alert">
        <ShieldAlert size={16} aria-hidden />
        <span>无法确认旧托管密钥是否已经退役。确认状态前，不应假设部署方已经失去旧数据的解密能力。</span>
      </div>
    );
  }

  const disclosure = describeRetirement(state.value);
  if (!disclosure) return null;
  return (
    <div
      className={[styles.banner, disclosure.danger ? styles.danger : ''].filter(Boolean).join(' ')}
      role={disclosure.danger ? 'alert' : 'status'}
    >
      <ShieldAlert size={16} aria-hidden />
      <span>{disclosure.message}</span>
    </div>
  );
}

export function describeRetirement(value: LegacyKeyRetirementResponse) {
  if (value.status === 'completed' || value.status === 'not_applicable') return null;
  if (value.migratedJobCount === 0) return null;
  if (value.status === 'unplanned') {
    return {
      danger: true,
      message: '旧数据已经切换为端到端加密，但部署方尚未登记旧托管密钥退役计划，仍可能解密迁移前的旧副本。',
    };
  }
  if (value.overdue) {
    return {
      danger: true,
      message: `旧数据已经切换为端到端加密，但旧托管密钥超过 ${formatDeadline(value.retireBy)} 仍未完成退役。部署方仍可能解密迁移前的旧副本。`,
    };
  }
  return {
    danger: false,
    message: `旧数据已经切换为端到端加密，旧托管密钥仍在受控保留期，计划最晚于 ${formatDeadline(value.retireBy)} 退役。完成证据登记前，部署方仍可能解密迁移前的旧副本。`,
  };
}

function formatDeadline(value: string | null): string {
  if (!value) return '尚未确定的期限';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '登记的期限';
  return new Intl.DateTimeFormat('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date);
}
