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

  if (readiness.ready) return null;

  if (assignmentGap === 0) {
    return (
      <div className={styles.adminProvisioningGuide} data-compact={compact}>
        <strong className={styles.adminProvisioningHeading}>
          管理员人数已满足，还有人需要完成首次使用
        </strong>
        <p>
          已设置 {readiness.administratorCount} 名管理员，其中 {readiness.readyAdministratorCount} 名已经可以参与确认。
          其余管理员登录一次、设置主密码并进入工作台后，再刷新本页即可。
        </p>
      </div>
    );
  }

  return (
    <div className={styles.adminProvisioningGuide} data-compact={compact}>
      <strong className={styles.adminProvisioningHeading}>
        <Settings2 size={15} aria-hidden />
        还需设置 {assignmentGap} 名恢复管理员
      </strong>
      <p>候选人先用公司账号登录平台一次，然后请有服务器权限的人按下面说明设置。平台内不能自行提升权限。</p>
      <details>
        <summary>服务器管理员操作说明</summary>
        <p>进入本项目的部署目录，在终端运行：</p>
        <div className={styles.adminCommandList} aria-label="恢复管理员维护命令">
          <code>{ADMIN_COMMANDS.list}</code>
          <code>{ADMIN_COMMANDS.grant}</code>
          {!compact && <code>{ADMIN_COMMANDS.revoke}</code>}
        </div>
        <p>&lt;登录用户名&gt; 填公司登录账号。更换人员时先撤销旧账号，再设置新账号。</p>
      </details>
      <p>设置完成后，该管理员登录并设置主密码即可。包括平台管理员也绝对无法查看受保护库。</p>
    </div>
  );
}
