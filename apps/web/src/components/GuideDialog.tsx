import * as Dialog from '@radix-ui/react-dialog';
import { X, ShieldCheck, Zap, Users, PlayCircle, ListChecks } from 'lucide-react';
import { ActionButton } from './ActionButton.tsx';
import dialogStyles from './dialog.module.css';
import styles from './GuideDialog.module.css';

/**
 * 新手指南："为什么使用Mima / 3 分钟入门"。
 * 登录前（登录页按钮）与登录后（Header 常驻入口）都可打开；
 * 登录后可从这里直接开始互动引导。文案面向普通员工，不出现技术术语——
 * 技术细节收在可展开的"安全原理"里。
 */
export function GuideDialog({
  open,
  onClose,
  onStartTour,
}: {
  open: boolean;
  onClose: () => void;
  /** 已登录时提供：关闭对话框并开始互动引导。 */
  onStartTour?: () => void;
}) {
  if (!open) return null;
  return (
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className={dialogStyles.overlay} />
        <Dialog.Content className={[dialogStyles.content, styles.content].join(' ')} aria-describedby={undefined}>
          <Dialog.Title className={dialogStyles.title}>为什么使用Mima？</Dialog.Title>
          <Dialog.Close asChild>
            <button className={dialogStyles.close} aria-label="关闭"><X size={16} /></button>
          </Dialog.Close>

          <p className={styles.lead}>先把个人使用走通，再按需要创建团队密码库。第一次照着下面的顺序做即可。</p>

          <section className={styles.section}>
            <h3 className={styles.sectionTitle}><ListChecks size={16} aria-hidden /> 先用起来</h3>
            <ol className={styles.list}>
              <li><strong>登录并解锁：</strong>通过平台官网、飞书或任何中间平台登录，再设置一个只在当前设备解密的主密码。</li>
              <li><strong>先用个人库：</strong>个人密码库已自动准备好；点库名旁的铅笔改名，然后新建第一条记录。</li>
              <li><strong>再建团队库：</strong>点“团队”右侧的加号，填写名称即可创建，默认由你担任拥有者。</li>
              <li><strong>添加同事：</strong>点团队库旁的成员按钮设置查看、编辑或审计权限。同事需要先登录一次并设置主密码，之后由密码库拥有者完成访问开通。</li>
              <li><strong>离开前锁定：</strong>点顶栏的锁定按钮；回来输入主密码即可继续。</li>
            </ol>
          </section>

          <details className={styles.details}>
            <summary><span className={styles.summaryLabel}><ShieldCheck size={16} aria-hidden /> 安全底线：放心存</span></summary>
            <ul className={styles.list}>
              <li>标题、用户名、网址、标签、密码、Token 和备注正文都先在你的设备上加密，服务器只保存加密后的数据。</li>
              <li>平台管理员可以管理账号和查看操作记录，但不能直接查看密码库名称、密码、Token 或备注。</li>
              <li>撤销授权后会立即停止在线访问；系统只在确有需要时更新密码库保护，不会让无关成员反复操作。</li>
              <li>点一下锁定会清除当前页面的解密能力，并遮罩刚才显示的内容。</li>
            </ul>
          </details>

          <details className={styles.details}>
            <summary><span className={styles.summaryLabel}><Zap size={16} aria-hidden /> 效率体验：用得快</span></summary>
            <ul className={styles.list}>
              <li>搜索和筛选在你自己的电脑上瞬间完成，打字即出结果，不用等网络。</li>
              <li>常用密码一键查看、一键复制；复制 30 秒后自动帮你清理剪贴板。</li>
              <li>浏览器扩展优先匹配<strong>完整登录地址</strong>，并在协议、域名和端口完全一致时提供同站点候选；相似域名不会进入建议填充。</li>
              <li>离线时可以使用此浏览器保存的数据，修改先在本机保护好，恢复网络后再同步。</li>
            </ul>
          </details>

          <details className={styles.details}>
            <summary><span className={styles.summaryLabel}><Users size={16} aria-hidden /> 团队协作：管得清</span></summary>
            <ul className={styles.list}>
              <li>个人库与团队库分开：个人库只属于你；团队库由拥有者决定谁能看、谁能改。</li>
              <li>需要合规检查？有"只能查记录、不能看密码"的审计角色。</li>
              <li>每条密码保留版本历史；多人同时修改时，先保存的内容生效，其他人的页面会暂停保存并保留草稿，引导先查看最新内容再处理自己的修改。</li>
              <li>企业恢复是可选能力，不影响先创建和使用。每次恢复都要两位管理员确认，再由三份离线材料中的任意两份共同处理，任何一人都不能单独恢复。</li>
            </ul>
          </details>

          <details className={styles.details}>
            <summary>安全原理（给好奇的同学）</summary>
            <ul className={styles.list}>
              <li>主密码只在本地解锁用户密钥；用户、设备、密码库和条目使用分层密钥。</li>
              <li>每个内容版本单独加密，并与所属密码库和条目绑定；密文被篡改或挪用时会拒绝解密。</li>
              <li>实时同步、离线缓存和待同步队列只保存密文、签名和版本号。</li>
            </ul>
          </details>

          <div className={styles.footer}>
            {onStartTour ? (
              <ActionButton label="开始 3 分钟入门" icon={<PlayCircle size={16} />} onClick={onStartTour} />
            ) : (
              <span className={styles.loginHint}>登录后可开始 3 分钟互动引导，逐个认识界面上的真实按钮。</span>
            )}
            <ActionButton label="知道了" variant="secondary" onClick={onClose} />
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
