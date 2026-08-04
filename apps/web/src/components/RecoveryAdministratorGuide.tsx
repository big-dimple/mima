import { Terminal } from 'lucide-react';
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
          管理员人数已满足，无需再次执行授权命令
        </strong>
        <p>
          已直授 {readiness.administratorCount} 名管理员，其中 {readiness.readyAdministratorCount} 名已准备。
          请按管理员列表补齐主密码、当前设备、实名 OIDC 或账号启用状态，然后重新登录或刷新本页。
        </p>
      </div>
    );
  }

  return (
    <div className={styles.adminProvisioningGuide} data-compact={compact}>
      <strong className={styles.adminProvisioningHeading}>
        <Terminal size={15} aria-hidden />
        还需直授 {assignmentGap} 名系统管理员
      </strong>
      <p>候选人先用企业账号登录平台一次，再由有服务器权限的运维人员进入部署目录执行：</p>
      <div className={styles.adminCommandList} aria-label="系统管理员维护命令">
        <code>{ADMIN_COMMANDS.list}</code>
        <code>{ADMIN_COMMANDS.grant}</code>
        {!compact && <code>{ADMIN_COMMANDS.revoke}</code>}
      </div>
      <p>
        命令中的 &lt;登录用户名&gt; 是登录用户名，不是显示名称。授权后，该管理员需设置主密码、准备当前设备，
        再重新登录或刷新本页。
      </p>
      {!compact && (
        <p>
          需要更换管理员时先用 revoke 撤销旧人，再用 grant 授予新人。平台不提供自助授予，避免账号自行提权；
          系统管理员角色本身不能解密或查看任何受保护密码库。
        </p>
      )}
    </div>
  );
}
