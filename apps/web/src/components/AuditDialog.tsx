import { useEffect, useState } from 'react';
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

  useEffect(() => {
    if (!vaultId) return;
    setEvents(null);
    setError(null);
    api.vaultAudit(vaultId)
      .then(setEvents)
      .catch((err) => setError(err instanceof Error ? err.message : '加载失败'));
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
                      <td className={styles.ts} data-label="时间">{e.ts.replace('T', ' ').slice(0, 19)}</td>
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
  'vault.delete': '删除密码库',
  'vault.rename': '修改密码库名称',
  'vault.transfer_ownership': '转移密码库所有权',
  'membership.set': '更新成员权限',
  'membership.remove': '移除成员权限',
  'group.create': '创建用户组',
  'group.rename': '修改用户组名称',
  'group.members_changed': '更新用户组成员',
  'group.transfer': '转移用户组',
  'group.delete': '删除用户组',
  'group.migrate': '迁移旧目录组',
  'item.create': '新建条目',
  'item.update_meta': '修改条目信息',
  'item.rotate_secret': '更新密码或敏感内容',
  'item.delete': '删除条目',
  'item.reveal': '旧版敏感内容读取',
  'item.e2ee.create': '写入加密条目',
  'item.e2ee.update_metadata': '更新加密条目信息',
  'item.e2ee.rotate_secret': '更新加密内容',
  'item.e2ee.delete': '删除加密条目',
  'item.e2ee.ciphertext_delivered': '在线投递密文',
  'crypto.profile.create': '创建用户加密资料',
  'crypto.device.register': '授权新设备',
  'crypto.device.revoke': '撤销设备',
  'recovery.request.create': '发起企业恢复',
  'recovery.request.approve': '审批企业恢复',
  'recovery.request.complete': '完成企业恢复',
  'extension.pair.created': '生成扩展配对码',
  'extension.pair.claimed': '扩展完成配对',
  'extension.unpair': '解除扩展配对',
  'system_role.migrate': '调整系统管理员',
};

function actionLabel(action: string): string {
  return ACTION_LABELS[action] ?? '系统操作';
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
