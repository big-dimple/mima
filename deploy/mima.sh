#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/compose.yaml"
RUNTIME_ENV="${MIMA_RUNTIME_ENV:-${SCRIPT_DIR}/runtime.env}"
BASE_DIR="${MIMA_BASE_DIR:-}"
COMPOSE_CMD=()

log() { printf '[Mima] %s\n' "$*"; }
fail() { printf '[Mima] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: ./deploy/mima.sh <command>

  init [--profile NAME]          初始化配置和私有运行目录
  doctor                         检查配置、权限、HTTPS 和 Compose
  up | down | status             启停或查看服务
  logs [SERVICE]                 查看日志
  directory preview | apply      预览或应用员工目录同步
  admin list                     列出系统管理员
  admin grant USERNAME           授予系统管理员
  admin revoke USERNAME          撤销系统管理员
  backup [OUTPUT_DIRECTORY]      创建一致性恢复包
  restore BUNDLE --confirm-empty 恢复到空运行目录
EOF
}

env_value() {
  local key="$1" value=''
  [[ -f "$RUNTIME_ENV" ]] || { printf ''; return; }
  value="$(sed -n "s/^${key}=//p" "$RUNTIME_ENV" | tail -n 1)"
  value="${value%$'\r'}"
  if [[ "$value" == \"*\" || "$value" == \'*\' ]]; then
    value="${value:1:${#value}-2}"
  fi
  printf '%s' "$value"
}

resolve_base_dir() {
  if [[ -z "$BASE_DIR" ]]; then BASE_DIR="$(env_value MIMA_BASE_DIR)"; fi
  if [[ -z "$BASE_DIR" ]]; then BASE_DIR="${REPO_ROOT}/.mima"; fi
  BASE_DIR="$(realpath -m -- "$BASE_DIR")"
  [[ "$BASE_DIR" != '/' && "$BASE_DIR" != "$REPO_ROOT" ]] || fail 'MIMA_BASE_DIR 不能是根目录或源码目录'
  export MIMA_BASE_DIR="$BASE_DIR"
  export MIMA_RUNTIME_ENV="$RUNTIME_ENV"
}

configure_compose() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=(docker compose)
  else
    fail '需要 Docker Compose v2'
  fi
}

load_compose_context() {
  command -v docker >/dev/null 2>&1 || fail '缺少 docker'
  [[ -f "$RUNTIME_ENV" ]] || fail "缺少运行配置，请先执行 init: ${RUNTIME_ENV}"
  chmod 0600 "$RUNTIME_ENV"
  resolve_base_dir
  load_identity
  configure_compose
}

compose() {
  "${COMPOSE_CMD[@]}" --env-file "$RUNTIME_ENV" -f "$COMPOSE_FILE" "$@"
}

private_file() {
  local path="$1" label="$2"
  [[ ! -L "$path" && -f "$path" && -s "$path" ]] || fail "${label} 缺失、为空或不是普通文件: ${path}"
  chmod 0600 "$path"
  [[ "$(stat -c '%a' "$path")" == '600' ]] || fail "${label} 权限必须是 0600: ${path}"
}

prepare_runtime() {
  install -d -m 0700 "$BASE_DIR" "$BASE_DIR/config" "$BASE_DIR/extension" \
    "$BASE_DIR/keys/runtime" "$BASE_DIR/keys/audit" "$BASE_DIR/keys/legacy-content" \
    "$BASE_DIR/migration-secrets" "$BASE_DIR/postgres" "$BASE_DIR/secrets" "$BASE_DIR/backups"
  install -m 0600 /dev/null "$BASE_DIR/README.txt"
  printf '%s\n' \
    'Mima 私有运行目录，禁止提交到 Git。' \
    'secrets/ 与 keys/ 必须随数据库一起备份；extension/ 决定扩展身份。' \
    'postgres/ 是数据库数据；backups/ 是未加密的敏感恢复包，应转移到加密离线存储。' \
    > "$BASE_DIR/README.txt"

  if [[ ! -e "$BASE_DIR/secrets/postgres-password" && ! -e "$BASE_DIR/secrets/database-url" ]]; then
    local password
    password="$(openssl rand -hex 32)"
    printf '%s\n' "$password" > "$BASE_DIR/secrets/postgres-password"
    printf 'postgres://mima:%s@postgres:5432/mima\n' "$password" > "$BASE_DIR/secrets/database-url"
    unset password
  fi
  private_file "$BASE_DIR/secrets/postgres-password" 'PostgreSQL 密码'
  private_file "$BASE_DIR/secrets/database-url" '数据库 URL'
  node "$REPO_ROOT/scripts/extension-identity.mjs" "$BASE_DIR/extension" >/dev/null
  export MIMA_EXTENSION_PUBLIC_KEY="$(<"$BASE_DIR/extension/manifest-public-key")"
  export MIMA_EXTENSION_IDS="$(<"$BASE_DIR/extension/extension-id")"
}

load_identity() {
  private_file "$BASE_DIR/extension/manifest-public-key" '扩展 manifest 公钥'
  private_file "$BASE_DIR/extension/extension-id" '扩展 ID'
  export MIMA_EXTENSION_PUBLIC_KEY="$(<"$BASE_DIR/extension/manifest-public-key")"
  export MIMA_EXTENSION_IDS="$(<"$BASE_DIR/extension/extension-id")"
  [[ "$MIMA_EXTENSION_IDS" =~ ^[a-p]{32}$ ]] || fail '扩展 ID 格式无效'
}

doctor() {
  command -v node >/dev/null 2>&1 || fail '缺少 Node.js 24+'
  command -v openssl >/dev/null 2>&1 || fail '缺少 openssl'
  [[ "$(node -p 'Number(process.versions.node.split(".")[0])')" -ge 24 ]] || fail '需要 Node.js 24 或更高版本'
  load_compose_context

  local public_url login_provider reauth_provider directory_provider bind_address
  public_url="$(env_value MIMA_PUBLIC_BASE_URL)"
  login_provider="$(env_value MIMA_LOGIN_PROVIDER)"
  reauth_provider="$(env_value MIMA_REAUTH_PROVIDER)"
  directory_provider="$(env_value MIMA_DIRECTORY_PROVIDER)"
  bind_address="$(env_value MIMA_BIND_ADDRESS)"
  [[ -n "$public_url" ]] || fail '必须设置 MIMA_PUBLIC_BASE_URL'
  node -e 'const u=new URL(process.argv[1]); if(u.protocol!=="https:"||u.username||u.password||u.pathname!=="/"||u.search||u.hash) process.exit(1)' "$public_url" \
    || fail 'MIMA_PUBLIC_BASE_URL 必须是无路径、查询和凭据的 HTTPS origin'
  [[ "$login_provider" == 'oidc' || "$login_provider" == 'ldap' || "$login_provider" == 'feishu' ]] \
    || fail '生产登录来源只能是 oidc、ldap 或 feishu'
  [[ "$reauth_provider" == 'none' ]] || fail 'E2EE 部署必须设置 MIMA_REAUTH_PROVIDER=none'
  [[ "$directory_provider" == 'ldap' || "$directory_provider" == 'authentik' ]] \
    || fail '生产员工目录只能是 ldap 或 authentik'
  [[ -z "$bind_address" || "$bind_address" == '127.0.0.1' || "$bind_address" == '::1' ]] \
    || fail 'Gateway 默认只允许绑定 loopback，请在前方使用 HTTPS 反向代理'
  [[ "$(env_value MIMA_E2EE_REQUIRED)" == 'true' ]] || fail '必须设置 MIMA_E2EE_REQUIRED=true'
  [[ "$(env_value MIMA_SESSION_COOKIE_SECURE)" == 'true' ]] || fail '必须启用安全 Cookie'

  private_file "$BASE_DIR/secrets/database-url" '数据库 URL'
  private_file "$BASE_DIR/secrets/postgres-password" 'PostgreSQL 密码'
  if [[ "$login_provider" == 'oidc' || "$(env_value MIMA_REAUTH_PROVIDER)" == 'oidc' ]]; then
    private_file "$BASE_DIR/secrets/oidc-client-secret" 'OIDC client secret'
  fi
  if [[ "$login_provider" == 'feishu' ]]; then
    private_file "$BASE_DIR/secrets/feishu-app-secret" '飞书应用密钥'
  fi
  if [[ "$login_provider" == 'ldap' || "$directory_provider" == 'ldap' ]]; then
    private_file "$BASE_DIR/secrets/ldap-bind-password" 'LDAP 只读账号密码'
    if [[ -n "$(env_value MIMA_LDAP_CA_FILE)" ]]; then
      private_file "$BASE_DIR/config/ldap-ca.pem" 'LDAP CA 证书'
    fi
  fi
  if [[ "$directory_provider" == 'authentik' ]]; then
    private_file "$BASE_DIR/secrets/directory-token" 'Authentik 目录 token'
  fi
  compose config >/dev/null
  log '配置、权限、扩展身份和 Compose 检查通过'
}

build_images() {
  compose --profile migration --profile migration-role --profile tools build \
    api migration migration-role gateway recovery-tool
}

ensure_postgres() {
  compose up -d postgres
  local attempt
  for attempt in $(seq 1 60); do
    if compose exec -T postgres pg_isready -U mima -d mima >/dev/null 2>&1; then return; fi
    sleep 1
  done
  fail 'PostgreSQL 未在 60 秒内就绪'
}

initialize_keys_and_schema() {
  compose run --rm --no-deps api node scripts/init-server-keys.mjs
  compose run --rm --no-deps api node apps/api/dist/db/migrate.js
}

command_init() {
  local profile='oidc-ldap'
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      --profile) profile="${2:-}"; shift 2 ;;
      *) fail "未知 init 参数: $1" ;;
    esac
  done
  [[ "$profile" =~ ^(oidc-ldap|ldap|oidc-authentik|feishu-ldap)$ ]] || fail '未知配置模板'
  [[ ! -e "$RUNTIME_ENV" ]] || fail "运行配置已存在，不会覆盖: ${RUNTIME_ENV}"
  install -m 0600 "$SCRIPT_DIR/profiles/${profile}.env.example" "$RUNTIME_ENV"
  resolve_base_dir
  prepare_runtime
  log "初始化完成: ${BASE_DIR}"
  log "请编辑 ${RUNTIME_ENV}，并把身份系统密钥写入 ${BASE_DIR}/secrets/ 后执行 doctor"
}

command_up() {
  doctor
  build_images
  ensure_postgres
  initialize_keys_and_schema
  compose run --rm --no-deps api node apps/api/dist/scripts/auth-doctor.js
  compose up -d api gateway
  compose ps
  log "Mima 已启动；公开入口应由 HTTPS 反向代理指向 127.0.0.1:${MIMA_PORT:-10087}"
}

command_directory() {
  local action="${1:-}"
  [[ "$action" == 'preview' || "$action" == 'apply' ]] || fail 'usage: directory preview | apply'
  doctor
  ensure_postgres
  local args=(node apps/api/dist/scripts/directory-sync.js)
  if [[ "$action" == 'apply' ]]; then args+=(--apply); fi
  compose run --rm --no-deps api "${args[@]}"
}

command_admin() {
  local action="${1:-}" username="${2:-}"
  [[ "$action" == 'list' || "$action" == 'grant' || "$action" == 'revoke' ]] || fail 'usage: admin list | admin <grant|revoke> USERNAME'
  if [[ "$action" != 'list' && -z "$username" ]]; then fail '缺少用户名'; fi
  doctor
  ensure_postgres
  local args=(node apps/api/dist/scripts/system-role.js "$action")
  if [[ -n "$username" ]]; then args+=("$username"); fi
  compose run --rm --no-deps api "${args[@]}"
}

command_backup() {
  doctor
  ensure_postgres
  local timestamp output temporary was_running=0
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  output="${1:-${BASE_DIR}/backups/mima-backup-${timestamp}}"
  output="$(realpath -m -- "$output")"
  [[ ! -e "$output" ]] || fail "备份目标已存在: ${output}"
  temporary="${output}.partial"
  [[ ! -e "$temporary" ]] || fail "残留临时备份需要人工检查: ${temporary}"
  install -d -m 0700 "$temporary/runtime"
  if compose ps --status running --services | grep -qx api; then was_running=1; fi
  compose stop gateway api >/dev/null 2>&1 || true
  restart_after_backup() {
    if [[ "$was_running" == '1' ]]; then compose up -d api gateway >/dev/null; fi
  }
  trap restart_after_backup EXIT
  compose run --rm --no-deps api node apps/api/dist/scripts/verify-audit.js
  compose exec -T postgres pg_dump -U mima -d mima -Fc > "$temporary/database.dump"
  compose exec -T postgres pg_restore --list < "$temporary/database.dump" >/dev/null
  cp -a "$BASE_DIR/config" "$BASE_DIR/extension" "$BASE_DIR/keys" "$BASE_DIR/secrets" "$temporary/runtime/"
  install -m 0600 "$RUNTIME_ENV" "$temporary/runtime/runtime.env"
  printf 'kind=mima-backup-v1\ncreated_at=%s\n' "$timestamp" > "$temporary/MANIFEST"
  (cd "$temporary" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
  chmod -R go-rwx "$temporary"
  mv "$temporary" "$output"
  restart_after_backup
  trap - EXIT
  log "备份完成: ${output}"
  log '恢复包包含数据库、运行密钥和身份系统密钥；请立即转移到加密离线存储'
}

command_restore() {
  local bundle="${1:-}" confirmation="${2:-}"
  [[ -d "$bundle" && "$confirmation" == '--confirm-empty' ]] || fail 'usage: restore BUNDLE --confirm-empty'
  bundle="$(realpath -- "$bundle")"
  (cd "$bundle" && grep -qx 'kind=mima-backup-v1' MANIFEST && sha256sum -c SHA256SUMS)
  resolve_base_dir
  if [[ -e "$BASE_DIR" ]] && find "$BASE_DIR" -mindepth 1 -print -quit | grep -q .; then
    fail "恢复只允许空运行目录: ${BASE_DIR}"
  fi
  [[ ! -e "$RUNTIME_ENV" ]] || fail "恢复不会覆盖现有配置: ${RUNTIME_ENV}"
  install -d -m 0700 "$BASE_DIR"
  cp -a "$bundle/runtime/." "$BASE_DIR/"
  mv "$BASE_DIR/runtime.env" "$RUNTIME_ENV"
  chmod 0600 "$RUNTIME_ENV"
  doctor
  ensure_postgres
  compose exec -T postgres pg_restore --clean --if-exists -U mima -d mima < "$bundle/database.dump"
  initialize_keys_and_schema
  compose run --rm --no-deps api node apps/api/dist/scripts/verify-audit.js
  compose up -d api gateway
  log '恢复完成，数据库、审计链和服务均已验证'
}

command="${1:-help}"
if [[ "$#" -gt 0 ]]; then shift; fi
case "$command" in
  init) command_init "$@" ;;
  doctor) doctor ;;
  up) command_up ;;
  down) load_compose_context; compose down ;;
  status) load_compose_context; compose ps ;;
  logs)
    load_compose_context
    if [[ -n "${1:-}" ]]; then compose logs -f -- "$1"; else compose logs -f; fi
    ;;
  directory) command_directory "$@" ;;
  admin) command_admin "$@" ;;
  backup) command_backup "$@" ;;
  restore) command_restore "$@" ;;
  help|-h|--help) usage ;;
  *) usage; fail "未知命令: ${command}" ;;
esac
