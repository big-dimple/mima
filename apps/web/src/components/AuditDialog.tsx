import { useEffect, useRef, useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { X } from 'lucide-react';
import type { AuditEvent } from '@mima/contracts';
import { useApp, useMeta } from '../state/app-context.ts';
import { useUi } from '../state/ui-store.ts';
import { ErrorState, LoadingState } from './AsyncState.tsx';
import dialogStyles from './dialog.module.css';
import styles from './AuditDialog.module.css';

export function AuditDialog() {
  const { api } = useApp();
  const vaultId = useUi((s) => s.auditDialogVaultId);
  const close = () => useUi.getState().openAudit(null);
  const vault = useMeta((s) => (vaultId ? s.vaults[vaultId] : undefined));
  const currentUser = useMeta((s) => s.user);
  const [events, setEvents] = useState<AuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);
  const requestRef = useRef(0);

  useEffect(() => {
    if (!vaultId) return;
    const requestId = ++requestRef.current;
    setEvents(null);
    setError(null);
    api.vaultAudit(vaultId)
      .then((value) => {
        if (requestRef.current === requestId) setEvents(value);
      })
      .catch((err) => {
        if (requestRef.current === requestId) setError(err instanceof Error ? err.message : '加载失败');
      });
    return () => {
      if (requestRef.current === requestId) requestRef.current += 1;
    };
  }, [api, vaultId, retryKey]);

  if (!vaultId) return null;

  return (
    <Dialog.Root open onOpenChange={(open) => !open && close()}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={[dialogStyles.content, styles.content].join(' ')}>
          <Dialog.Title className={dialogStyles.title}>审计日志 · {vault?.name ?? ''}</Dialog.Title>
          <Dialog.Description className={dialogStyles.description}>
            记录权限变更、密文写入和在线密文投递。这里只显示脱敏字段，不能证明用户是否真的在本地查看或复制。
          </Dialog.Description>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭"><X size={16} /></button>
          </Dialog.Close>
          {error && (
            <ErrorState
              message={error}
              onRetry={() => setRetryKey((value) => value + 1)}
            />
          )}
          {!error && events === null && <LoadingState label="正在加载审计记录…" />}
          {events && events.length === 0 && <div className={styles.empty}>暂无审计记录</div>}
          {events && events.length > 0 && (
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr><th>时间</th><th>操作者</th><th>动作</th><th>结果</th></tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id} className={e.success ? '' : styles.failed}>
                      <td className={styles.ts} data-label="时间">{formatAuditTime(e.ts)}</td>
                      <td data-label="操作者" title={e.actorUserId ?? undefined}>{actorLabel(e.actorUserId, currentUser)}</td>
                      <td className={styles.action} data-label="动作">{actionLabel(e.action)}</td>
                      <td className={styles.result} data-label="结果">{e.success ? '成功' : <span className={styles.fail}>失败</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <p className={styles.note}>服务端用原始审计链和数据库外锚点检查完整性；本页不返回历史详情字段。</p>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

const ACTION_LABELS: Record<string, string> = {
  'session.login': '登录',
  'session.logout': '退出登录',
  'session.lock': '锁定工作台',
  'session.unlock': '解锁工作台',
  'session.crypto_unlock': '设备签名解锁',
  'session.backchannel_logout': '统一退出登录',
  'session.feishu_callback': '飞书登录回调',
  'session.oidc_callback': '统一认证回调',
  'vault.create': '创建密码库',
  'vault.create_pending_e2ee': '创建待初始化密码库',
  'vault.e2ee.initialize': '初始化密码库加密',
  'vault.e2ee.rekey': '更新密码库访问密钥',
  'vault.envelope_task.complete': '完成成员访问开通',
  'vault.ownership_transfer.request': '发起密码库所有权转移',
  'vault.ownership_transfer.accept': '接收密码库所有权',
  'vault.project.create': '创建项目',
  'vault.rekey.cancel_noop': '确认无需更新访问密钥',
  'vault.uninitialized.delete': '删除未初始化密码库',
  'vault.delete': '删除密码库',
  'vault.rename': '修改密码库名称',
  'vault.transfer_ownership': '转移密码库所有权',
  'membership.set': '更新成员权限',
  'membership.remove': '移除成员权限',
  'membership.e2ee.set': '更新加密密码库成员权限',
  'membership.e2ee.remove': '移除加密密码库成员权限',
  'group.create': '创建用户组',
  'group.rename': '修改用户组名称',
  'group.members_changed': '更新用户组成员',
  'group.transfer': '转移用户组',
  'group.delete': '删除用户组',
  'group.authorization_removed': '移除用户组授权',
  'group.migrate': '迁移旧目录组',
  'item.create': '新建条目',
  'item.update_meta': '修改条目信息',
  'item.rotate_secret': '更新密码或敏感内容',
  'item.delete': '删除条目',
  'item.reveal': '旧版敏感内容读取',
  'item.e2ee.create': '写入加密条目',
  'item.e2ee.update_metadata': '更新加密条目信息',
  'item.e2ee.update_meta': '更新加密条目信息',
  'item.e2ee.rotate_secret': '更新加密内容',
  'item.e2ee.delete': '删除加密条目',
  'item.e2ee.ciphertext_delivered': '在线投递密文',
  'crypto.profile.create': '创建用户加密资料',
  'crypto.profile.rewrap': '更新主密码保护',
  'crypto.profile.rotate': '轮换用户加密身份',
  'crypto.account_reset.create': '发起账户加密身份重置',
  'crypto.account_reset.approve': '审批账户加密身份重置',
  'crypto.account_reset.activate': '启用新的账户加密身份',
  'crypto.account_reset.cancel': '取消账户加密身份重置',
  'crypto.device.register': '授权新设备',
  'crypto.device.revoke': '撤销设备',
  'recovery.request.create': '发起企业恢复',
  'recovery.request.approve': '审批企业恢复',
  'recovery.request.complete': '完成企业恢复',
  'recovery.request.cancel': '取消企业恢复',
  'recovery.key.register': '登记企业恢复密钥',
  'recovery.key.approve': '审批企业恢复密钥',
  'recovery.key.activate': '启用企业恢复密钥',
  'recovery.key.cancel': '取消企业恢复密钥',
  'recovery.key.distribute': '分发企业恢复密钥',
  'extension.pair.created': '生成扩展配对码',
  'extension.pair.claimed': '扩展完成配对',
  'extension.e2ee.pairing.create': '生成扩展配对码',
  'extension.e2ee.enrollment.approve': '批准扩展设备',
  'extension.e2ee.session.resume': '恢复扩展在线连接',
  'extension.unpair': '解除扩展配对',
  'system_role.migrate': '调整系统管理员',
};

function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? `其他系统操作（${action}）`;
}

function formatAuditTime(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime())
    ? value
    : parsed.toLocaleString('zh-CN', { hour12: false });
}

function actorLabel(
  actorUserId: string | null,
  currentUser: { id: string; displayName: string } | null,
): string {
  if (!actorUserId) return '系统';
  if (actorUserId === currentUser?.id) return currentUser.displayName;
  if (actorUserId.length <= 18) return actorUserId;
  return `${actorUserId.slice(0, 8)}…${actorUserId.slice(-6)}`;
}
