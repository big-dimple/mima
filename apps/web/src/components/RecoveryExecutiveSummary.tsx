import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, ShieldCheck, UsersRound, XCircle } from 'lucide-react';
import type {
  EnterpriseRecoveryCoverage,
  EnterpriseRecoveryKey,
  EnterpriseRecoveryReadiness,
} from '@mima/contracts';
import { useApp } from '../state/app-context.ts';
import styles from './RecoveryDialog.module.css';

interface SummaryState {
  status: 'not-ready' | 'incomplete' | 'ready';
  label: '未准备' | '待完善' | '可以恢复';
  nextAction: string;
  key: EnterpriseRecoveryKey | null;
  readiness: EnterpriseRecoveryReadiness;
  coverage: EnterpriseRecoveryCoverage | null;
}

export function RecoveryExecutiveSummary() {
  const { api } = useApp();
  const [state, setState] = useState<SummaryState | null>(null);

  const load = useCallback(async () => {
    try {
      const [keys, readiness] = await Promise.all([
        api.recoveryKeys(),
        api.recoveryReadiness(),
      ]);
      const key = keys.find((entry) => entry.status === 'active')
        ?? keys.find((entry) => entry.status === 'staged' || entry.status === 'pending')
        ?? null;
      const coverage = key && (key.status === 'active' || key.status === 'staged')
        ? await api.recoveryCoverage(key.id)
        : null;
      if (key?.status === 'active' && readiness.ready && coverage?.complete === true) {
        setState({
          status: 'ready',
          label: '可以恢复',
          nextAction: '当前已具备联合恢复能力。每次实际恢复仍需两位管理员确认和两份离线材料。',
          key,
          readiness,
          coverage,
        });
        return;
      }
      if (key || readiness.readyAdministratorCount > 0) {
        const nextAction = !readiness.ready
          ? `先补齐三位管理员，目前已准备 ${readiness.readyAdministratorCount}/${readiness.requiredAdministratorCount}。`
          : !key
            ? '下一步是在隔离设备生成三份恢复材料，并登记公开清单。'
            : key.status === 'pending'
              ? '下一步由第二位管理员核对并确认同一份公开清单。'
              : coverage?.complete !== true
                ? '下一步由密码库所有者为尚未覆盖的密码库添加恢复保护。'
                : key.status === 'staged'
                  ? '全部准备已经完成，可以正式启用企业恢复。'
                  : '当前恢复材料已启用；请重新核对管理员和密码库覆盖状态。';
        setState({ status: 'incomplete', label: '待完善', nextAction, key, readiness, coverage });
        return;
      }
      setState({
        status: 'not-ready',
        label: '未准备',
        nextAction: '日常密码库不受影响。需要企业兜底时，从准备三位管理员开始。',
        key,
        readiness,
        coverage,
      });
    } catch {
      setState(null);
    }
  }, [api]);

  useEffect(() => {
    void load();
    const refresh = () => void load();
    window.addEventListener('mima:recovery-key-updated', refresh);
    window.addEventListener('mima:recovery-coverage-updated', refresh);
    return () => {
      window.removeEventListener('mima:recovery-key-updated', refresh);
      window.removeEventListener('mima:recovery-coverage-updated', refresh);
    };
  }, [load]);

  return (
    <section className={styles.executiveSummary} data-state={state?.status ?? 'not-ready'} data-recovery-tour="recovery-overview">
      <div className={styles.summaryHeading}>
        <div>
          <span className={styles.summaryEyebrow}>企业恢复保障状态</span>
          <strong>{state?.label ?? '正在核对'}</strong>
        </div>
        <ShieldCheck size={24} aria-hidden />
      </div>
      <p className={styles.summaryNext}>{state?.nextAction ?? '正在核对当前准备情况。'}</p>
      <ul className={styles.assuranceList}>
        <li><UsersRound size={16} aria-hidden /><span><strong>任何一个人都不能单独恢复</strong>每次需要两位管理员确认，并由三份离线材料中的任意两份共同完成。</span></li>
        <li><CheckCircle2 size={16} aria-hidden /><span><strong>只恢复已纳入保护的密码库</strong>恢复的是指定访问能力，不会找回员工旧主密码。</span></li>
        <li><ShieldCheck size={16} aria-hidden /><span><strong>全过程可以核对</strong>申请、两人确认、离线处理和目标设备验证都会留下审计记录。</span></li>
        <li><XCircle size={16} aria-hidden /><span><strong>个人库不能转交给别人</strong>只有原所有者仍具合法归属时，才能恢复到申请绑定的本人设备；管理员不能借此接管或查看。</span></li>
      </ul>
      <div className={styles.managementPrimer}>
        <div>
          <h3>哪些情况会用到</h3>
          <ul>
            <li><strong>忘记主密码且没有可用设备：</strong>先重置密码库解锁；团队库优先由仍能打开的所有者重新授权。</li>
            <li><strong>设备损坏或丢失：</strong>先使用其他可信设备；所有设备都不可用时再判断是否需要恢复。</li>
            <li><strong>离职未完成交接：</strong>只处理已纳入保护、且接收人本来就有权限的团队库；不能借恢复新增权限。</li>
            <li><strong>个人库无法打开：</strong>只有已纳入保护的个人库，才能恢复给仍具归属的原所有者本人。</li>
          </ul>
        </div>
        <div>
          <h3>真正恢复时怎么做</h3>
          <ol>
            <li>确认恢复场景、团队库和接收人。</li>
            <li>系统检查接收人已有合法权限。</li>
            <li>两位管理员分别确认本次申请。</li>
            <li>两位材料保管人在隔离设备共同处理。</li>
            <li>目标设备验证结果并生成审计记录。</li>
          </ol>
        </div>
      </div>
    </section>
  );
}
