import { Settings2 } from 'lucide-react';
import type { EnterpriseRecoveryReadiness } from '@mima/contracts';
import styles from './RecoveryDialog.module.css';

const ADMIN_COMMANDS = {
  list: './deploy/mima.sh admin list',
  grant: './deploy/mima.sh admin grant <登录用户名>',
  revoke: './deploy/mima.sh admin revoke <登录用户名>',
};

export function RecoveryAdministratorGuide({
  readiness,
  compact = false,
}: {
  readiness: EnterpriseRecoveryReadiness;
  compact?: boolean;
}) {
  const assignmentGap = Math.max(
    readiness.requiredAdministratorCount - readiness.administratorCount,
    0,
  );

  return (
    <div className={styles.adminProvisioningGuide} data-compact={compact} data-ready={readiness.ready}>
      <strong className={styles.adminProvisioningHeading}>
        <Settings2 size={15} aria-hidden />
        {readiness.ready
          ? '当前恢复管理员（每次由其中两位确认）'
          : assignmentGap > 0
            ? `还需设置 ${assignmentGap} 名恢复管理员`
            : '管理员人数已满足，还有人需要完成首次使用'}
      </strong>
      <p>公司预先设置 3 名恢复管理员，是为了其中一人忘记主密码时，仍有另外两人可以确认；每次帮助普通用户恢复只需要其中两位。</p>
      {readiness.administrators.length > 0 && (
        <ul className={styles.adminReadinessList} aria-label="当前恢复管理员">
          {readiness.administrators.map((administrator) => (
            <li key={administrator.userId} data-ready={administrator.ready}>
              <div>
                <strong>{administrator.displayName}</strong>
                <span>{administrator.username}</span>
              </div>
              <span>{administratorStatus(administrator)}</span>
            </li>
          ))}
        </ul>
      )}
      {!readiness.ready && (
        <p>候选人先用公司账号登录平台一次，然后请有服务器权限的人按下面说明设置。平台内不能自行提升权限。</p>
      )}
      <details>
        <summary>{readiness.ready ? '查看或更换恢复管理员' : '服务器管理员操作说明'}</summary>
        <p>进入本项目的部署目录，在终端运行：</p>
        <div className={styles.adminCommandList} aria-label="恢复管理员维护命令">
          <code>{ADMIN_COMMANDS.list}</code>
          <code>{ADMIN_COMMANDS.grant}</code>
          <code>{ADMIN_COMMANDS.revoke}</code>
        </div>
        <p>&lt;登录用户名&gt; 填公司登录账号。更换人员时先撤销旧账号，再设置新账号。</p>
      </details>
      {!readiness.ready && <p>设置完成后，该管理员登录并设置主密码即可。包括平台管理员也绝对无法查看受保护库。</p>}
    </div>
  );
}

function administratorStatus(
  administrator: EnterpriseRecoveryReadiness['administrators'][number],
): string {
  if (administrator.ready) return '可参与确认';
  if (!administrator.active) return '账号已停用';
  if (administrator.identitySource !== 'oidc') return '需要使用公司统一登录';
  if (!administrator.hasCryptoProfile) return '尚未设置主密码';
  return '需要重新登录一次';
}
