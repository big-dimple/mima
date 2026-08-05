# Mima

Mima 是一个面向团队、自托管的端到端加密凭证管理系统。它提供 Web 工作台、Chrome/Edge 扩展、团队密码库、用户组授权、离线使用、审计和可选的企业恢复能力。

> 当前版本为 `0.2.0`。公开仓库只支持全新安装，不支持导入本项目开源前的私有数据库或运行目录。

## 主要能力

- **客户端加密**：主密码、密码库名称和库内内容都不会以明文发送到服务器，包括平台管理员也绝对无法查看受保护库。
- **团队协作**：个人库、团队库、用户组、四级角色、后台逐用户密钥交付和并发写入保护。
- **企业身份**：支持 OIDC、LDAP/AD、Authentik 目录和飞书登录组合。
- **浏览器扩展**：Chrome/Edge MV3 扩展支持配对、解锁联动、多个登录网址的搜索匹配、复制和填充。
- **离线工作**：Web 与扩展只缓存密文，重新联网后校验权限并同步待办操作。
- **恢复与审计**：可选的双管理员审批、三份材料取二的离线企业恢复，以及可校验的审计链。

Mima 的服务端仍能看到用户、授权关系、对象 ID、版本、时间、密文长度、IP 和访问模式。它无法抵御恶意前端构建、终端木马、键盘记录、屏幕录制、浏览器漏洞或已授权成员主动外传。完整边界见 [SECURITY.md](SECURITY.md)。

## 首次使用

1. 用户先通过部署方配置的身份入口登录；这一步只确认身份，不能解锁密码库。
2. 用户在浏览器中设置主密码，本机生成账户和设备密钥；主密码和私钥不上传。
3. 客户端自动初始化唯一的个人密码库，名称为“我的密码库”，随后直接进入工作台，不再要求先填写库名。
4. 当前浏览器首次进入工作台时直接启动一次互动引导；完成、跳过或中断后不会再次自动启动，仍可从顶栏手动打开。
5. 用户或用户组授权保存后无需拥有者再次逐人开通。成员首次设置主密码或更换加密代次时，系统会自动通知已解锁拥有者客户端补齐独立密钥信封；如果所有拥有者都离线，成员暂时看到“正在自动准备团队访问”，下一位拥有者解锁或重连后自动完成。

忘记主密码时，用户直接联系公司管理员。管理员在企业恢复中心发起协助，用户设置一次新主密码即可离开页面；第二位管理员确认后系统自动启用新主密码并注销旧登录，用户可从任意浏览器重新登录并自动接回原有访问，不需要返回设置新主密码时使用的浏览器。系统只恢复用户原本仍然有效的密码库权限；不会找回旧主密码、不会让管理员登录用户账号，也不会给任何人新增权限。

## 本地体验

准备：

- Node.js 24 或更高版本
- pnpm 10.33.2（Corepack 可安装）
- Docker

```bash
corepack enable
corepack prepare pnpm@10.33.2 --activate
pnpm install --frozen-lockfile
pnpm demo
```

打开 <http://127.0.0.1:4173>，使用本地演示账号 `alice` / `dev`。该账号只能在显式 Demo 模式和回环地址上启用，不能用于生产。

扩展构建在 `apps/extension/dist`。在 `chrome://extensions` 或 `edge://extensions` 开启开发者模式后，选择“加载已解压的扩展程序”。按 `Ctrl+C` 停止 Web/API，再执行以下命令停止 Demo PostgreSQL：

```bash
pnpm demo:down
```

Demo 数据和本地密钥保存在被 Git 忽略的 `.mima/demo/`。停止服务不会删除它；需要重新开始时，应在确认没有要保留的数据后自行删除该目录。

默认端口被占用时，可通过 `MIMA_DEMO_WEB_PORT`、`MIMA_DEMO_API_PORT` 和 `MIMA_DEMO_POSTGRES_PORT` 覆盖；并行体验多个副本时还应设置不同的 `MIMA_DEMO_POSTGRES_CONTAINER`。

## 生产部署

生产使用 Docker Compose，并在前方配置 HTTPS 反向代理：

```bash
./deploy/mima.sh init --profile oidc-ldap
# 编辑 deploy/runtime.env，并写入所需密钥
./deploy/mima.sh doctor
./deploy/mima.sh up
```

支持的配置模板为 `oidc-ldap`、`ldap`、`oidc-authentik` 和 `feishu-ldap`。部署前务必阅读 [DEPLOYMENT.md](DEPLOYMENT.md)，尤其是运行目录、扩展身份、备份和恢复章节。

## 运行数据

源码与运行数据严格分离：

- `deploy/runtime.env`：当前部署的非密钥配置，权限为 `0600`，不提交 Git。
- `.mima/`：默认私有运行目录，保存数据库、服务端密钥、扩展身份和备份，不提交 Git。
- `.mima/extension/`：决定扩展 ID；丢失后重新构建的扩展会被浏览器视为另一个扩展。
- `.mima/keys/` 与 `.mima/secrets/`：必须和数据库作为同一恢复点备份。
- `.mima/backups/`：包含可恢复整个部署的敏感材料，默认未额外加密，必须转移到加密离线存储。

不要把 `.mima/` 当作缓存，也不要只备份 PostgreSQL。

## 开发

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm test:e2e
pnpm api:specs:check
pnpm db:migrations:check
pnpm public:audit
pnpm build
pnpm runtime:scan
```

数据库迁移文件已建立哈希锁。已有迁移不得修改；结构变化只能新增迁移，并更新 `apps/api/src/db/migration-lock.json`。

## 工程结构

```text
apps/
  api/            身份、授权、密文存储、审计、SSE 和状态机
  web/            React 工作台、Crypto Worker 和本地解锁
  extension/      Chrome/Edge MV3 扩展
  recovery-tool/  企业恢复离线工具
packages/
  contracts/      REST、SSE 和密码学数据契约
  e2ee/           端到端加密协议实现
  client-core/    客户端密钥环、密文缓存、Outbox 和同步
  domain/         角色、权限、目录和条目领域逻辑
  crypto/         服务端审计与受控旧格式迁移组件
  ui-tokens/      Web 与扩展共享样式变量
deploy/           Compose、镜像构建、配置模板和运维脚本
```

## 文档

- [DEPLOYMENT.md](DEPLOYMENT.md)：部署、运维、备份与恢复
- [SECURITY.md](SECURITY.md)：安全模型、限制和漏洞报告
- [LLMWIKI.md](LLMWIKI.md)：提供给 AI 和二次开发者的代码导航与不可破坏契约

## 许可证

Mima 使用 [Apache License 2.0](LICENSE)。
