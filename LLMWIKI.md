# Mima LLM Wiki

本文件是 AI 与二次开发者的稳定入口。它描述当前架构、不可破坏的安全/并发契约、代码地图和验证方法，不记录某次部署、真实人员、服务器、密钥、镜像摘要或临时待办。

## 先读什么

1. `README.md`：产品范围、本地 Demo 和工程入口。
2. `SECURITY.md`：威胁模型、密码学边界和漏洞报告。
3. 本文件：实现契约和代码导航。
4. 涉及自托管时再读 `DEPLOYMENT.md`。

权威顺序是：代码与 SQL > 生成的 OpenAPI/AsyncAPI > 本文件 > README/部署说明。发现冲突时，以可验证实现为准，并在同一次修改中修正文档。

## 当前基线

- 版本：`0.2.0`
- Node.js：24+
- 包管理器：pnpm 10.33.2
- 数据库：PostgreSQL 18 Compose 基线
- E2EE 协议标识：`lm-e2ee-v1`（为兼容保持此名称）
- 数据库迁移头：`0025_nonblocking_initial_recovery`
- 元数据格式：v5；v4 数据可读，写入与 rekey 只允许 v5
- vault header：v3；兼容读取 v2/v3，新写入只允许 v3
- 公开仓库只承诺全新安装，不承诺兼容开源前的私有数据库或运行目录

## 架构

```text
Browser
  Web React app + dedicated Crypto Worker
  Chrome/Edge MV3 extension + Service Worker + Crypto Worker
        |
        | HTTPS, ciphertext, signatures, opaque IDs
        v
gateway (Nginx static files + /api proxy)
        |
        v
Fastify API ---- PostgreSQL
  auth/RBAC       ciphertext, public keys, envelopes,
  versioning      versions, authorization, audit
  signatures
  SSE
```

常驻生产容器只有 `gateway`、`api`、`postgres`。migration worker 和 recovery tool 是隔离、按需运行的任务。

### 技术路线

- 当前仓库没有 Backstage Catalog、TechDocs 或 `@backstage/*` 运行依赖；身份、目录和部署接口均可独立使用。
- React + Vite 负责浏览器工作台并保持 Crypto Worker 边界；Fastify + Zod + Drizzle 负责轻量、可审计的 API 与数据库契约；PostgreSQL 承担事务、锁、约束和并发一致性。这些选择与自托管 E2EE 场景匹配，不因项目早期接入过 Backstage 而重写。
- 不为“通用化”引入新的应用框架、插件系统或数据库抽象层。只有出现可复现的外部接入需求时，才在现有认证与目录接口后增加 Provider，并用兼容测试固定行为。
- 框架或存储路线调整必须由实际维护成本、兼容需求或性能证据驱动，并先完成加密协议、迁移和回滚影响评审。

## 代码地图

### 应用

- `apps/api/src/strict-app.ts`：严格 E2EE API 组合入口。
- `apps/api/src/env.ts`：环境变量、安全启动门禁和 Demo 限制。
- `apps/api/src/routes/e2ee-*.ts`：账户、设备、密码库、密文、扩展、恢复、事件和换钥协议。
- `apps/api/src/routes/e2ee-recovery-cases.ts`：管理员发起、用户准备、双人确认、批量离线结果和领取前过滤的恢复案件状态机。
- `apps/api/src/services/access.ts`：有效权限计算。
- `apps/api/src/services/audit.ts`：链式审计和库外 anchor。
- `apps/api/src/services/extension-sessions.ts`：扩展在线会话与交接。
- `apps/api/src/db/schema.ts`：Drizzle 查询模型。
- `apps/api/src/db/schema.sql`、`migrations/*.sql`：数据库真相。
- `apps/web/src/App.tsx`：认证、解锁和工作台顶层状态。
- `apps/web/src/crypto/`：专用 Crypto Worker；私钥和明文处理不得回退到主线程。
- `apps/web/src/components/Workspace.tsx`：三栏工作台编排。
- `apps/web/src/components/VaultNav.tsx`：个人/团队/项目/目录树。
- `apps/web/src/components/ItemForm.tsx`：新建与编辑条目。
- `apps/web/src/hooks/useIntentionalTextField.ts`：只接受用户主动输入，阻止浏览器自动填充覆盖数据。
- `apps/extension/src/background-coordinator.ts`：扩展全局会话状态机。
- `apps/extension/src/trusted-unlock-bridge.ts`：工作台可信解锁联动。
- `apps/extension/src/workbench-wake.ts`：唤醒唯一可响应工作台端点。
- `apps/recovery-tool/src/cli.ts`：完全离线的恢复材料生成、检查和联合处理。

### 共享包

- `packages/e2ee`：唯一的新 E2EE 密码学实现、AAD 和测试向量。
- `packages/contracts`：REST、SSE、密文、设备、信封、恢复与迁移契约。
- `packages/client-core`：客户端密钥环、加密 IndexedDB、Outbox、同步和零知识操作。
- `packages/domain`：角色、目录路径、条目展示、网站匹配和密码生成。
- `packages/crypto`：服务端审计及受控旧格式工具；不得引入用户 E2EE 私钥。
- `packages/ui-tokens`：Web 与扩展共享设计变量。

### 生成物与门禁

- `apps/api/openapi/openapi.json`：生成的 REST 规范。
- `apps/api/openapi/asyncapi.json`：生成的事件规范。
- `apps/api/src/db/migration-lock.json`：迁移文件摘要基线。
- `scripts/verify-strict-runtime.mjs`：扫描构建产物是否混入禁用实现或依赖。
- `scripts/public-audit.mjs`：公开仓库品牌、身份、地址、文档和运行文件审计。

## 不可破坏的契约

### 1. 零知识边界

服务端可以看到用户、外部身份映射、设备公钥、个人/团队类别、owner、成员、用户组、角色、opaque ID、epoch、版本、删除标记、时间、密文长度、IP、User-Agent、cursor 和访问模式。

服务端不得得到主密码、派生钥匙、用户/设备私钥、活动 VMK/VCK/EVK、密码库名称、条目类型、标题、账号、网址、说明、关联信息、目录、标签、收藏、敏感级别、密码、Token、备注正文或明文搜索索引。

API 只校验身份、权限、结构、签名、版本和状态转换。不要在 API 中复制客户端解密逻辑，也不要为了搜索或审计把元数据改回明文。

### 2. 身份、解锁与管理员

- OIDC、LDAP/AD、飞书和 Authentik 只确认身份，不能解锁密码库。
- SSO 成功后的状态仍是 `authenticated-locked`。
- 主密码只在客户端用于解包随机 Account Key，不上传服务端。
- 首次建立加密资料后，已解锁客户端自动初始化唯一的个人密码库，解密后的固定名称为“我的密码库”，随后直接进入工作台。
- `platform-admin` 只来自 `system_role_assignments` 的显式本地授予。
- 任何用户组名称或外部组映射都不能隐式授予平台管理员。
- 平台管理员不自动获得密码库密钥；它仍需被 owner 像普通成员一样授权。
- Dev 登录、Dev reauth 和 Dev directory 必须同时满足 `MIMA_DEMO_MODE=true` 与回环 API/Web origin。

### 3. 密码学与密钥层级

- 主密码 KDF：libsodium Argon2id 1.3，随机 16 字节 salt、64 MiB、3 次、parallelism 1、输出 32 字节。
- 对称 AEAD：XChaCha20-Poly1305-IETF。
- 收件人信封：X25519 sealed box。
- 操作签名：Ed25519 detached signature。
- 公共二进制字段：无 padding base64url。
- 主密码派生钥匙只包装随机 Account Key；Account Key 包装用户/设备私钥。
- 用户/设备公钥接收逐密码库 epoch 的 VMK/VCK 信封。
- VMK 加密 vault header 和条目元数据；VCK 包装逐内容版本 EVK；EVK 加密敏感正文。
- 撤权时轮换 epoch、重加密元数据并重包 EVK，不批量重加密全部历史正文。

修改算法、参数、AAD、规范化 JSON、签名载荷或信封格式必须新建协议版本，并提供固定向量、跨端兼容和降级拒绝测试。

### 4. 锁定、离线与扩展

安全状态主干：

```text
unauthenticated
  -> setup-required | authenticated-locked
  -> unlocking
  -> unlocked-online | unlocked-offline
  -> rekey-blocked
```

- API 会话失效不等于断网：只有传输不可达才能显示“离线”。401 且存在本机密文缓存时应引导重新登录，并可由用户明确进入“本机模式”；没有缓存的首次访问保持普通登录。本机模式下同步和权限管理暂停；返回登录前必须先锁定并销毁解密能力，且不得清除设备配对或本机密文缓存。
- 锁定先推进安全代际，再销毁 Crypto Worker 中的私钥、VMK/VCK/EVK、解密投影、表单和搜索索引。
- Worker 失败时保持锁定，不能回退到主线程持有密钥。
- IndexedDB/extension storage 只保存加密账户包、公开设备信息、密文缓存和签名密文命令。
- 离线编辑进入加密 Outbox；重连先完成在线 challenge、回放事件、核对权限/epoch，最后串行冲刷。
- 扩展 bearer 只由 Service Worker 协调器管理；Side Panel 不直接读写 bearer storage。
- 配对后主密码、Account Key 和私钥不跨 Web/扩展传递。
- 同一账号只允许最近明确活动且可响应的 v2 工作台主端点参与可信解锁；其他标签待命。
- 一次可信解锁从派发到 bootstrap 完成必须串行并固定同一 bearer 快照，晚到的 401 或其他标签不能清除/替换它。
- 主动锁定、撤销设备、解除配对或身份密钥轮换必须立即失效。
- 扩展身份由 manifest 公钥决定。生产必须为每个部署生成并备份稳定身份，升级时不能重新生成。

### 5. 密码库、项目、目录与授权

- 密码库是唯一授权边界；目录只组织库内条目，不创建权限。
- 个人库不可分享。团队库支持直接用户和平台用户组授权。
- 角色为 `auditor`、`viewer`、`editor`、`owner`。
- `auditor` 只取得 metadata capability；其他角色取得 full capability；服务端 RBAC 仍独立裁决写入和成员管理。
- 直接用户角色存在时覆盖组角色，否则取组角色最高权限。
- 用户组只表达授权集合，不持有组密钥。
- 直接用户或平台用户组角色保存即完成产品侧授权，不存在拥有者再次逐人开通的流程。服务端只维护逐用户内部任务，不生成密码库密钥。
- 已解锁 owner 客户端在保存授权、收到 `vault.crypto_changed` 并刷新、解锁或重连时按密码库去重并串行处理任务；整库完成后只刷新一次。网络失败保留任务，404/409 视为其他 owner 已处理或授权已变化，刷新后结束本轮。
- 成员首次建立 crypto profile、加密代次变化或目录同步新增组成员时，服务端重建当前代任务并发布既有 `vault.crypto_changed` 事件。队列只处理仍有效、具有当前 `recipientProfile` 的普通授权任务；所有权转移任务必须排除。
- 已授权但尚无当前信封的成员只取得不含加密 header、条目或内容的团队库外壳，并显示“正在自动准备团队访问”；任一 owner 下次解锁或重连后自动补齐。
- 团队库必须始终保留至少一名活动、已准备加密资料、持有当前 epoch full 信封的直接 owner。
- owner 转移必须先让新 owner 取得当前 full 信封，再由其活动设备签署接受。
- 团队库默认扁平。项目是可选导航关系，但每个项目本身仍是独立团队密码库，拥有独立 owner、成员、密钥、条目、目录和审计。
- 项目不继承上级库权限，最多一层，不允许嵌套或创建后换父级。
- 目录最多五层。目录改名通过 header 中的加密别名映射，不逐条改写条目。
- 删除目录只允许删除没有活动条目的整棵空子树。
- “未分类”只在当前库确有未归类条目时显示。
- 删除团队库前必须在同一事务中锁定并再次确认活动条目为零、解密目录为零、调用者仍是 owner、header 版本未变化。

### 6. 原子性与并发

- 新建团队库/项目由客户端预生成 UUID、完整加密 header、epoch、持有证明和初始信封；API 单事务写入。
- 网络重试必须复用 UUID/幂等键。失败要么零写入，要么返回已完成的同一结果。
- 成员授权、用户组变更、换钥、owner 转移和删除都必须在事务内锁定并比较版本/revision。
- 每次实际信封交付继续校验 owner 身份、活动解锁设备、实时角色、vault epoch、收件人公钥代次、签名和任务 CAS，并保留审计记录；自动化不能降低任何校验。
- 409/412/426 等协议状态不能原样展示给普通用户；前端应保留草稿，用人话说明谁的状态已变化以及刷新、重试或联系谁。
- 并发冲突不能静默覆盖远端数据，也不能因为浏览器自动填充而把非用户输入当成修改。
- 编辑表单的初始值、浏览器 autofill、异步详情和用户输入必须分源跟踪。只有明确用户输入可以产生更新 patch。
- 元数据写入与 rekey 必须签名覆盖 `metadataFormatVersion=5`。缺失或 v2-v4 写入应被明确要求升级，不能把 `loginUrls` 等新 metadata 降级写回；扩展密文读取兼容 v4/v5，使既有配对设备可以继续读取主网址兼容字段。
- 已删除条目的墓碑是终态证据，换钥与元数据解析必须排除 tombstone。

### 7. 企业恢复

- 默认关闭，不阻塞普通使用。
- 管理员候选只来自显式本地直授的活动 OIDC `platform-admin`，且必须已经完成首次使用；平台角色本身不授予任何密码库内容权限。
- 恢复公钥和每次恢复案件都只接受精确两名不同管理员确认，目标用户不能确认自己的案件。状态转换必须在事务内锁定并重新核对；第三份审批、过期或取消、恢复密钥轮换、密码库 epoch 变化和收件人公钥代次变化都必须拒绝。
- 忘记主密码由管理员先发起案件，用户只设置一次新主密码即可离开。第二位管理员确认后服务端验证一次性预签授权、自动启用新加密代次并注销旧登录，用户可从任意浏览器重新登录。案件一次绑定其当时仍然有效的全部原有密码库权限，不向用户暴露申请入口、处理包、设备选择或密码学字段。
- 有 owner 能解锁时，owner 客户端自动满足对应子任务；没有 owner 能解锁时，一个案件文件覆盖案件内全部未完成子任务。离线结果上传后，用户可从任意浏览器用新主密码解锁，由当前活动登录自动领取、校验和完成，不依赖最初设置新主密码的浏览器。
- 离线恢复密钥拆成三份 `.mimashare`，放在三个独立位置；任意两份只能在隔离终端联合使用，不存在产品内“材料保管人”角色。
- ZIP 顶层必须提供可直接双击的“打开企业恢复向导.html”。向导默认只显示“首次准备”；处理具体案件必须显式切换到“处理恢复案件”，并选择从该案件下载的 JSON 文件和两份不同材料。误选首次准备生成的公开清单时必须明确解释文件用途。Node.js 命令行入口只能放在 `advanced/` 作为受控环境兜底。
- “准备恢复”必须始终列出当前三名恢复管理员的姓名、登录账号和准备状态，明确三人是预备名单、每次案件只需其中两人确认；断网说明必须直接解释为避免恢复材料接触服务器或网络。
- “恢复案件”选择用户必须复用服务端姓名/域账号搜索组件，支持通过拼音域账号查找，不加载全公司下拉名单、不默认选中第一人；审批后仍需离线联合处理时，状态和待办角标必须继续提醒管理员，不能伪装成已经自动完成。
- 服务器只保存恢复公钥、指纹、ceremony digest、代际、审批和 opaque evidence，不保存 share。
- 案件子任务必须绑定 active recovery key、密码库 `keyEpoch`、目标用户当前公钥代次、能力和创建时已经验证的签名者快照。完成前再次计算实时授权；撤权、降级、旧公钥、旧 epoch、旧恢复 key 和过期任务不得交付。
- 幂等键同时绑定命令名和请求摘要；同一键重试相同请求可以复用结果，同一键提交不同内容必须拒绝。
- 恢复不能新增权限，不能恢复旧主密码；团队库只恢复给仍有合法权限的用户，个人库只恢复给原所有者。
- 第二名管理员确认恢复公钥时，服务端向现有 E2EE 密码库发布 `vault.crypto_changed`，当前确认人的已解锁客户端也立即刷新；owner 客户端在后台写入恢复信封，服务端不能自行生成。首次启用不等待离线 owner，未覆盖密码库在对应 owner 下次事件、解锁或重连时自动补齐；更换活动恢复公钥仍必须先覆盖全部当前 epoch，不能留下旧恢复能力空档。

### 8. 迁移、审计与运行文件

- `schema.sql` 和已经存在的版本化迁移不可修改。
- 所有迁移摘要必须匹配 `migration-lock.json`；新增迁移后显式更新锁并评审差异。
- 审计链依赖数据库记录、audit key 和库外 anchor。不能用新 key 重签已有历史。
- `.mima/keys`、`.mima/secrets`、`.mima/extension` 和数据库必须作为同一恢复点备份。
- `.mima`、`deploy/runtime.env`、数据库 dump、私钥和恢复材料不得提交 Git。
- 公开仓库没有旧私有 Git 历史，也不提供旧私有数据库兼容承诺。

## 关键 UX 契约

- 普通界面使用“密码、Token、敏感内容、密码库、查看、登录密码或域密码”，避免把内部术语直接暴露给用户。
- 错误先说业务结果、影响、处理人和下一步，不直接显示 HTTP 状态码、epoch、envelope、Worker 或内部错误码。
- 企业恢复界面只说明“管理员发起、用户设置一次新主密码、两人确认、系统恢复原有权限”。用户设置后可以离开页面；第二位管理员确认会自动启用新主密码并注销旧登录，之后可从任意浏览器重新登录。不得要求用户选择浏览器或设备，不得把公钥、代次、信封、摘要、处理包等工程语言展示给普通用户。
- 不给每个控件堆解释文字；只在第一次使用、危险动作或状态确实容易误解时提供短说明。
- 设置主密码后不再设置个人库名称门槛；客户端自动创建“我的密码库”并进入工作台。当前浏览器首次进入工作台直接开始互动引导，完成、跳过或中断后都不再自动开始。
- 成员管理和用户组页面不显示内部任务数、访问状态列或逐人开通按钮。只有权利已经保存但信封仍在自动准备的成员，才在自己的密码库视图看到临时状态。
- 密码可以为空。账号密码可按顺序保存最多 10 个 HTTP(S) 网址，第一个是主网址；团队库可以只保存标题/账号/网址，用于共享入口或搜索。
- 条目类型保持克制：账号密码、API 凭证、安全备注。账号密码也用于服务器、数据库和其他账号类资源。
- 三种类型在筛选、表单和详情中复用独立低饱和色图标；新建表单只展开本类型核心字段，说明、标签、收藏和高敏标记由“添加字段”按需显示。已有可选值必须可发现且不得因收起而被覆盖。
- 敏感标记只有“普通/高敏”，只影响视觉分类，不改变权限或审计。
- 左侧树的名称负责选择，箭头负责展开；个人区、团队区、密码库、项目区、目录区和父目录都可独立收起，不强制保留一个展开项。
- 树展开状态只属于当前解锁会话；锁定/退出清除。远端新增节点不自动展开。
- 条目拖拽只在桌面细指针和当前库可写时启用；可接收目录要有明确外框。触屏使用“移动到目录”对话框。
- 三栏默认宽度为导航 384px、条目 420px；窄视口可以临时收紧，但不能覆盖用户保存的首选宽度。

## API 与事件

接口契约集中在 `packages/contracts`，API 路由通过 `apps/api/src/openapi-contract.ts` 生成 OpenAPI。SSE 事件生成 AsyncAPI。

修改接口或事件时：

1. 先修改共享契约和对应解析测试。
2. 修改 API 路由/服务。
3. 修改 client-core、Web 和扩展调用方。
4. 运行 `pnpm api:specs:generate`。
5. 检查生成 diff，再运行 `pnpm api:specs:check`。

不要手工编辑 JSON 规范。

## 数据库修改

1. 在 `apps/api/src/db/migrations/` 新增下一个顺序 SQL 文件。
2. 同步 `apps/api/src/db/schema.ts`；如基线建库也需要该结构，再追加到正确迁移链，不重写旧 SQL。
3. 更新 `apps/api/src/db/migration-lock.json` 中的文件和摘要。
4. 添加迁移、并发和回滚边界测试。
5. 运行 `pnpm db:migrations:check`、集成测试和完整构建。

不得通过修改旧迁移摘要来“修复”门禁失败。

## 本地运行与验证

最短本地体验：

```bash
pnpm install --frozen-lockfile
pnpm demo
```

质量门禁从小到大运行：

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm test:integration
pnpm api:specs:check
pnpm db:migrations:check
pnpm public:audit
pnpm build
pnpm runtime:scan
pnpm test:e2e
```

测试项目：

- `unit`：领域、密码学、client-core、API 纯逻辑。
- `web`：React 组件、交互、状态和可访问性。
- `extension`：扩展协调器、配对、恢复和填充。
- `integration`：真实 PostgreSQL、API 权限、事务和迁移。
- `e2e`：真实 Web/API/数据库/扩展浏览器流程。

修改多标签扩展解锁、Service Worker、浏览器 autofill、拖拽或响应式布局时，单元测试不足；必须增加对应多上下文或 Playwright 场景。扩展唤醒链路至少要故意丢弃一次 `unlocked=true` 工作台状态，并证明健康的已解锁工作台会以更高状态代次权威重放，且不要求刷新工作台或重新配对。

WSL 镜像网络若重置 IPv4 localhost，可用 `MIMA_E2E_API_HOST=::1` 让 API 与 Vite proxy 走 IPv6 回环；数据库可通过 `MIMA_E2E_DATABASE_URL` 或 `MIMA_INTEGRATION_DATABASE_URL` 指向独立测试实例。不要为绕过本机网络问题而放宽 Demo 到非回环地址。

## 部署实现

- `deploy/mima.sh`：唯一公共运维入口，支持 `init/doctor/up/down/status/logs/directory/admin/backup/restore`。
- `deploy/compose.yaml`：服务拓扑和最小权限容器配置。
- `deploy/Dockerfile`：Node 24 多阶段构建、严格运行时扫描、扩展/恢复工具打包。
- `deploy/profiles/*.env.example`：四套身份组合模板。
- `scripts/extension-identity.mjs`：生成并验证每个部署的稳定扩展 manifest 身份。

改变部署脚本时至少运行 `bash -n deploy/mima.sh`、临时目录 `init`、`doctor` 的成功/失败路径、Compose config、备份清单和空目录恢复保护。任何会删除或覆盖运行数据的动作都必须失败关闭并要求显式确认。

## 常见改动路径

- 新增条目字段：`contracts` -> `e2ee item/AAD` -> `client-core` -> `ItemForm/ItemDetail` -> extension -> 格式版本和迁移测试。
- 改角色权限：`packages/domain/src/roles.ts` -> API `access.ts`/routes -> client guards -> 成员 UI -> 集成测试。
- 改目录/项目树：`vault header` 契约 -> domain -> client projection -> `VaultNav` -> 并发/header 防降级测试。
- 改扩展解锁：background coordinator -> trusted bridge/workbench wake -> API extension sessions -> 多标签/重启/失效 E2E。
- 改认证：env/provider -> callback/session -> identity mapping -> auth doctor -> 部署模板；不得触碰本地解锁层。
- 改恢复：contracts/e2ee -> API recovery state machine -> Web approval/coverage -> offline tool -> 两管理员与 2-of-3 测试。
- 改可见文案：检查同一状态在 Web、扩展和 API 错误映射中的一致性，保持“结果、影响、下一步”。

## 完成定义

一个改动只有在以下条件同时满足时才算完成：

- 安全、权限、原子性和失败关闭契约未被削弱；
- 新行为有与风险相称的自动化测试；
- 生成规范和迁移锁没有漂移；
- 构建产物通过 strict runtime scan；
- 公开审计没有企业、个人、真实地址、旧品牌或运行材料残留；
- README、部署、安全或本文件中受影响的说明已经同步；
- 没有把真实凭证、截图、数据库或恢复材料带入仓库。
