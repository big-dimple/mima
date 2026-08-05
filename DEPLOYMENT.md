# Mima 部署指南

本文面向首次自托管 Mima 的管理员。公开版本只支持全新安装；不要把开源前的私有数据库、密钥或 Compose 运行目录接入本仓库。

## 1. 架构与前提

常驻服务只有三个：

- `gateway`：静态 Web、扩展下载和 API 反向代理
- `api`：身份、授权、密文存储、审计和同步
- `postgres`：业务数据库

`migration`、`migration-role` 和 `recovery-tool` 是按需任务，不是在线服务。

主机需要：

- Linux x86_64/arm64
- Docker Engine 与 Docker Compose v2
- Node.js 24 或更高版本
- OpenSSL
- 一个 HTTPS 域名和外部反向代理
- OIDC、LDAP/AD、Authentik 或飞书中的至少一套可用身份配置

默认只在 `127.0.0.1:10087` 暴露 gateway。TLS 必须在同机或可信内网中的反向代理终止，不应直接把该端口开放到公网。

## 2. 初始化

选择最接近组织现状的模板：

```bash
./deploy/mima.sh init --profile oidc-ldap
```

可选模板：

| 模板 | 登录 | 员工目录 |
| --- | --- | --- |
| `oidc-ldap` | OIDC | LDAP/AD |
| `ldap` | LDAP/AD | LDAP/AD |
| `oidc-authentik` | OIDC | Authentik |
| `feishu-ldap` | 飞书 | LDAP/AD |

初始化会创建：

```text
deploy/runtime.env       当前部署配置，0600
.mima/
  README.txt             运行目录说明
  config/                CA 等非环境文件配置
  extension/             manifest 公钥与稳定扩展 ID
  keys/                  运行密钥、审计密钥和迁移密钥目录
  postgres/              PostgreSQL 数据
  secrets/               数据库与身份系统密钥
  migration-secrets/     受控迁移任务密钥
  backups/               本机备份暂存区
```

这两个位置都已加入 `.gitignore`。它们不是构建缓存，不能在升级、重新拉取源码或清理磁盘时删除。需要把运行数据放到源码之外时，可在初始化前指定绝对路径：

```bash
MIMA_BASE_DIR=/srv/mima ./deploy/mima.sh init --profile oidc-ldap
```

随后在 `deploy/runtime.env` 中增加 `MIMA_BASE_DIR=/srv/mima`，或每次执行命令时提供同一环境变量。

## 3. 配置身份与密钥

编辑 `deploy/runtime.env`，至少替换域名、稳定部署 ID、回调地址、Issuer、Client ID、LDAP DN 等示例值。`MIMA_PUBLIC_BASE_URL` 必须是没有路径、查询参数或凭据的 HTTPS origin。

密钥不写入环境文件，按所选模板创建对应文件：

| 场景 | 文件 |
| --- | --- |
| OIDC 登录 | `.mima/secrets/oidc-client-secret` |
| 飞书登录 | `.mima/secrets/feishu-app-secret` |
| LDAP 登录或目录 | `.mima/secrets/ldap-bind-password` |
| Authentik 目录 | `.mima/secrets/directory-token` |
| 私有 LDAP CA | `.mima/config/ldap-ca.pem` |

所有密钥文件必须是普通文件、非空且权限为 `0600`：

```bash
install -m 0600 /dev/null .mima/secrets/oidc-client-secret
printf '%s\n' 'replace-me' > .mima/secrets/oidc-client-secret
chmod 0600 .mima/secrets/oidc-client-secret
```

LDAP 必须使用 `ldaps://` 并验证证书链与主机名。不要复用个人账号或其他系统的高权限目录凭据，建议创建只读服务账号。

## 4. HTTPS 反向代理

以下 Nginx 片段仅展示关键转发项；证书、HSTS、日志和访问控制应按组织标准配置：

```nginx
server {
    listen 443 ssl http2;
    server_name mima.example.com;

    location / {
        proxy_pass http://127.0.0.1:10087;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_buffering off;
        proxy_read_timeout 1h;
    }
}
```

身份系统中的回调地址必须与 `runtime.env` 完全一致，例如：

- OIDC：`https://mima.example.com/api/auth/oidc/callback`
- 飞书：`https://mima.example.com/api/auth/feishu/callback`

## 5. 检查并启动

```bash
./deploy/mima.sh doctor
./deploy/mima.sh up
./deploy/mima.sh status
```

`doctor` 会检查 Node、Docker、HTTPS origin、E2EE 配置、身份来源、私有文件权限、扩展身份和 Compose 渲染。`up` 会构建镜像、启动 PostgreSQL、初始化服务端密钥、执行迁移、检查认证配置并启动 API/gateway。

常用排障命令：

```bash
./deploy/mima.sh logs
./deploy/mima.sh logs api
./deploy/mima.sh status
./deploy/mima.sh down
```

`down/status/logs` 使用轻量运行态检查，即使身份配置暂时有误，也不会被完整 `doctor` 阻挡。

## 6. 首次使用与管理员

1. 先让用户通过组织登录进入一次，系统才会创建活动用户记录。
2. 用户在浏览器中设置主密码并生成本地加密资料。客户端会自动创建唯一的个人密码库“我的密码库”，直接进入工作台，并在当前浏览器首次进入时启动一次新手引导。
3. 团队库保存用户或用户组授权后不需要管理员再次逐人开通。成员后设主密码时，系统会通知已解锁拥有者客户端自动补齐；没有已解锁拥有者时只会暂时等待，下一位拥有者解锁或重连后继续。
4. 如需平台管理员，由服务器管理员显式授予：

```bash
./deploy/mima.sh admin list
./deploy/mima.sh admin grant alice
./deploy/mima.sh admin revoke alice
```

用户组名称或身份系统中的同名组不会自动获得平台管理员权限。平台管理员也不会自动取得任何密码库的解密密钥；主密码、密码库名称和库内内容都不会以明文发送到服务器。

员工目录同步先预览再应用：

```bash
./deploy/mima.sh directory preview
./deploy/mima.sh directory apply
```

## 7. 浏览器扩展身份

首次初始化会为当前部署生成稳定的 Chrome 扩展身份：

- `.mima/extension/manifest-public-key`
- `.mima/extension/extension-id`

它们不是用于解密用户数据的私钥，但决定浏览器识别到的扩展 ID。每次构建必须沿用同一份身份；丢失或重新生成后，浏览器会把扩展视为另一个扩展，用户需要重新安装和配对。

`up` 构建的 gateway 会在 `/downloads/` 提供当前扩展压缩包。开发者模式安装时，先解压再选择“加载已解压的扩展程序”。升级同一扩展时保留原目录并覆盖文件，然后在扩展管理页点击“重新加载”；不要先删除扩展，否则浏览器本地配对状态也会被删除。

## 8. 备份

创建一致性恢复包：

```bash
./deploy/mima.sh backup
# 或指定新目录
./deploy/mima.sh backup /mnt/secure/mima-backup-20260726
```

脚本会短暂停止 API/gateway，校验审计链，创建 PostgreSQL 自校验 dump，并复制运行密钥、审计密钥、身份系统密钥、CA、扩展身份和配置。原本在运行的服务会自动恢复。

恢复包默认未额外加密，足以恢复整个部署。创建后应立即转移到加密离线存储，并按组织制度限制访问。企业恢复的 `.mimashare` 文件不属于服务器备份，必须分别保存在独立位置。

只备份数据库是不完整的：缺少 `.mima/keys` 会破坏审计与运行能力，缺少 `.mima/extension` 会改变扩展身份。

## 9. 恢复演练

恢复只允许写入空运行目录和不存在的 `runtime.env`，避免覆盖仍可用的数据：

```bash
MIMA_BASE_DIR=/srv/mima-restored \
MIMA_RUNTIME_ENV=/etc/mima/runtime.env \
./deploy/mima.sh restore /mnt/secure/mima-backup-20260726 --confirm-empty
```

脚本会校验清单与所有文件摘要，恢复数据库和运行材料，执行迁移，验证审计链后启动服务。建议定期在隔离主机演练，并验证登录、解锁、扩展 ID 和历史审计。

## 10. 更新

发布更新前：

1. 阅读目标版本说明并确认 Node/Docker 要求。
2. 执行 `./deploy/mima.sh backup`，把恢复包转移到安全位置。
3. 保留原 `deploy/runtime.env` 和完整 `.mima/`。
4. 更新源码后运行 `pnpm install --frozen-lockfile`。
5. 执行 `pnpm db:migrations:check` 和 `./deploy/mima.sh doctor`。
6. 执行 `./deploy/mima.sh up`。

不要修改已经发布的 SQL 迁移。迁移哈希不匹配时应停止更新并检查源码来源，不能跳过门禁。

保存过备用网址后，普通应用回滚目标必须支持 metadata v5；只理解 v4 的旧页面或 rekey 会丢弃备用网址。此时应向前修复，或恢复到写入这些数据前的完整一致性备份，不能只回滚应用容器。

## 11. 企业恢复

企业恢复默认关闭，也不影响普通使用。启用后，包括平台管理员也绝对无法查看受保护库；管理员只帮助用户恢复原本仍然有效的权限，不能找回旧主密码、登录用户账号或新增密码库权限。

工作台的企业恢复中心按“总览、准备恢复、恢复案件、历史记录”组织。首次准备只需：

1. 从页面下载 ZIP，带到断网电脑，解压并双击“打开企业恢复向导.html”；无需安装 Node.js，也不用填写编号、目录或材料名称。
2. 向导一次生成“企业恢复公开清单.json”和三份恢复材料。三份材料分别保存在三个独立位置，只把公开清单带回平台登记。
3. 另一位平台管理员进入同一页面确认。已解锁的密码库拥有者客户端会在后台自动补齐保护，完成后系统自动启用，不需要管理员逐库点击。

企业恢复要求至少三名本地直授平台管理员完成首次使用。服务器管理员使用以下命令查看、设置或更换人员，页面在人数不足时也会显示同样的相对命令：

```bash
./deploy/mima.sh admin list
./deploy/mima.sh admin grant alice
./deploy/mima.sh admin revoke alice
```

同事忘记主密码时，管理员在“恢复案件”选择本人并发起协助，用户设置一次新主密码即可离开页面，两位不同管理员分别确认本人身份。第二位确认后系统自动启用新主密码并注销旧登录，用户可从任意浏览器重新登录并自动接回原有访问，不需要返回设置新主密码时使用的浏览器。系统优先由仍能打开密码库的拥有者自动恢复；确实无人能打开时，管理员只需下载一个案件处理包，在断网电脑选择该处理包和任意两份不同材料，再上传一个处理结果。一个案件会批量处理用户仍有权访问的全部密码库，撤权、降级、换钥或过期项目会自动跳过，用户不接触工具或文件。

不要把恢复材料上传到服务器、Git、聊天、工单或普通备份。Compose `tools` profile 和命令行工具只保留给不能运行 HTML 向导的受控环境，不是日常入口。

## 12. 上线检查表

- HTTPS、回调地址和反向代理头正确
- `MIMA_BIND_ADDRESS` 保持回环地址
- Demo/dev 登录未启用
- 身份和目录服务账号遵循最小权限
- `.mima`、`runtime.env` 和所有密钥权限正确
- 至少完成一次备份与隔离恢复演练
- 备份、日志和监控中没有主密码、Token、Cookie 或恢复材料
- 扩展 ID 与备份中的身份一致
- 管理员由 CLI 显式授予，不依赖用户组名称
