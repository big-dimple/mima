type JsonObject = Record<string, unknown>;

type OperationMetadata = {
  operationId: string;
  summary: string;
  tag: string;
  security: 'public' | 'web' | 'extension';
  csrf?: boolean;
};

export interface OpenApiBuildOptions {
  pruneUndocumented?: boolean;
}

const OPERATIONS: Record<string, OperationMetadata> = {
  'GET /api/auth/config': op('getAuthConfig', '读取当前认证方式', '认证与会话', 'public'),
  'GET /api/auth/dev-users': op('listDevelopmentUsers', '列出本地开发身份', '认证与会话', 'public'),
  'GET /api/auth/oidc/start': op('startOidcLogin', '启动组织统一认证', '认证与会话', 'public'),
  'POST /api/auth/oidc/callback': op('completeOidcLogin', '处理组织统一认证回调', '认证与会话', 'public'),
  'GET /api/auth/feishu/start': op('startFeishuLogin', '启动飞书登录', '认证与会话', 'public'),
  'GET /api/auth/feishu/callback': op('completeFeishuLogin', '处理飞书登录回调', '认证与会话', 'public'),
  'GET /api/session': op('getSession', '读取当前 Web 会话', '认证与会话', 'web'),
  'POST /api/session': op('createDevelopmentSession', '创建本地开发会话', '认证与会话', 'public'),
  'DELETE /api/session': op('deleteSession', '退出当前 Web 会话', '认证与会话', 'web', true),
  'POST /api/session/lock': op('lockSession', '锁定当前 Web 会话', '认证与会话', 'web', true),
  'POST /api/session/unlock': op('unlockPasswordSession', '停用旧登录因子解锁', '认证与会话', 'web', true),
  'POST /api/session/reauth': op('startSessionReauthentication', '停用统一认证解锁', '认证与会话', 'web', true),
  'POST /api/auth/oidc/backchannel-logout': op('consumeOidcBackchannelLogout', '处理统一退出登录通知', '认证与会话', 'public'),
  'GET /api/directory': op('listDirectorySubjects', '读取可授权用户和用户组', '认证与会话', 'web'),
  'GET /api/users/search': op('searchUsers', '搜索可授权用户', '认证与会话', 'web'),
  'GET /api/groups': op('listCustomGroups', '搜索平台用户组', '用户组', 'web'),
  'GET /api/groups/{groupId}': op('getCustomGroup', '读取平台用户组', '用户组', 'web'),
  'POST /api/groups': op('createCustomGroup', '创建平台用户组', '用户组', 'web', true),
  'PATCH /api/groups/{groupId}': op('renameCustomGroup', '修改平台用户组名称', '用户组', 'web', true),
  'PUT /api/groups/{groupId}': op('updateCustomGroup', '原子更新平台用户组', '用户组', 'web', true),
  'PUT /api/groups/{groupId}/members': op('setCustomGroupMembers', '更新平台用户组成员', '用户组', 'web', true),
  'POST /api/groups/{groupId}/transfer': op('transferCustomGroup', '转移平台用户组', '用户组', 'web', true),
  'DELETE /api/groups/{groupId}': op('deleteCustomGroup', '删除平台用户组', '用户组', 'web', true),
  'GET /api/healthz': op('getHealth', '读取服务健康状态', '运行状态', 'public'),
  'GET /api/readyz': op('getReadiness', '读取服务就绪状态', '运行状态', 'public'),
  'GET /api/vaults/{vaultId}/audit': op('listVaultAuditEvents', '读取密码库审计记录', '审计', 'web'),
  'GET /api/v2/events': op('streamEncryptedSyncEvents', '订阅零知识密文事件流', '同步', 'web'),
  'GET /api/v2/bootstrap': op('getEncryptedBootstrap', '读取零知识工作台快照', '同步', 'web'),
  'GET /api/v2/crypto/profile': op('getCryptoProfile', '读取用户加密资料', '认证与会话', 'web'),
  'POST /api/v2/crypto/profile': op('createCryptoProfile', '初始化用户加密资料', '认证与会话', 'web', true),
  'PUT /api/v2/crypto/profile': op('rewrapCryptoProfile', '更新主密码密钥包装', '认证与会话', 'web', true),
  'POST /api/v2/crypto/profile/rotate': op('rotateCryptoProfile', '轮换用户身份密钥', '认证与会话', 'web', true),
  'POST /api/v2/crypto/public-profiles': op('getPublicCryptoProfiles', '批量读取成员公钥', '认证与会话', 'web', true),
  'GET /api/v2/devices': op('listCryptoDevices', '读取授权设备', '认证与会话', 'web'),
  'POST /api/v2/devices': op('registerCryptoDevice', '登记授权设备', '认证与会话', 'web', true),
  'POST /api/v2/devices/{deviceId}/revoke': op('revokeCryptoDevice', '撤销授权设备', '认证与会话', 'web', true),
  'POST /api/v2/session/unlock-challenge': op('createCryptoUnlockChallenge', '创建本地解锁挑战', '认证与会话', 'web', true),
  'POST /api/v2/session/crypto-unlock': op('completeCryptoUnlock', '完成本地设备签名解锁', '认证与会话', 'web', true),
  'GET /api/v2/account-crypto-resets': op('listAccountCryptoResets', '读取账户重置申请', '账户恢复', 'web'),
  'GET /api/v2/account-crypto-resets/{requestId}': op('getAccountCryptoReset', '读取账户重置申请详情', '账户恢复', 'web'),
  'POST /api/v2/account-crypto-resets': op('createAccountCryptoReset', '发起账户加密资料重置', '账户恢复', 'web', true),
  'POST /api/v2/account-crypto-resets/{requestId}/approve': op('approveAccountCryptoReset', '审批账户重置', '账户恢复', 'web', true),
  'POST /api/v2/account-crypto-resets/{requestId}/cancel': op('cancelAccountCryptoReset', '取消账户重置', '账户恢复', 'web', true),
  'POST /api/v2/account-crypto-resets/{requestId}/activate': op('activateAccountCryptoReset', '启用新的账户加密资料', '账户恢复', 'web', true),
  'GET /api/v2/legacy-key-retirement': op('getLegacyKeyRetirement', '读取旧密钥退役状态', '迁移', 'web'),
  'POST /api/v2/legacy-key-retirement': op('createLegacyKeyRetirement', '登记旧密钥退役计划', '迁移', 'web', true),
  'POST /api/v2/legacy-key-retirement/approve': op('approveLegacyKeyRetirement', '审批旧密钥退役计划', '迁移', 'web', true),
  'POST /api/v2/legacy-key-retirement/complete': op('completeLegacyKeyRetirement', '确认旧密钥退役完成', '迁移', 'web', true),
  'POST /api/v2/vaults': op('createEncryptedVault', '创建零知识团队密码库', '密码库', 'web', true),
  'POST /api/v2/vaults/{vaultId}/projects': op('createEncryptedProject', '在团队密码库下创建独立权限项目', '密码库', 'web', true),
  'DELETE /api/v2/vaults/{vaultId}': op('deleteEncryptedVault', '永久删除零知识团队密码库', '密码库', 'web', true),
  'DELETE /api/v2/vaults/{vaultId}/uninitialized': op('deleteUninitializedVault', '清理未初始化的空团队密码库', '密码库', 'web', true),
  'POST /api/v2/vaults/{vaultId}/initialize': op('initializeVaultCrypto', '初始化密码库密钥', '密码库', 'web', true),
  'PATCH /api/v2/vaults/{vaultId}/header': op('renameEncryptedVault', '修改密码库名称密文', '密码库', 'web', true),
  'PUT /api/v2/vaults/{vaultId}/members': op('setEncryptedVaultMember', '授权成员并安排密钥分发', '密码库', 'web', true),
  'DELETE /api/v2/vaults/{vaultId}/members': op('removeEncryptedVaultMember', '撤销成员并冻结轮换', '密码库', 'web', true),
  'GET /api/v2/vaults/{vaultId}/envelope-tasks': op('listVaultEnvelopeTasks', '读取待分发成员密钥任务', '密码库', 'web'),
  'GET /api/v2/envelope-tasks/mine': op('listMyEnvelopeTasks', '读取与当前用户相关的密钥任务', '密码库', 'web'),
  'POST /api/v2/vaults/{vaultId}/envelope-tasks/{taskId}/complete': op('completeVaultEnvelopeTask', '提交成员密钥信封', '密码库', 'web', true),
  'GET /api/v2/vaults/{vaultId}/ownership-transfer': op('getVaultOwnershipTransfer', '读取所有权转移状态', '密码库', 'web'),
  'POST /api/v2/vaults/{vaultId}/ownership-transfer': op('createVaultOwnershipTransfer', '发起所有权转移', '密码库', 'web', true),
  'POST /api/v2/vaults/{vaultId}/ownership-transfer/accept': op('acceptVaultOwnershipTransfer', '目标用户确认接收所有权', '密码库', 'web', true),
  'POST /api/v2/vaults/{vaultId}/ownership-transfer/cancel': op('cancelVaultOwnershipTransfer', '取消或拒绝所有权转移', '密码库', 'web', true),
  'POST /api/v2/vaults/{vaultId}/items': op('createEncryptedItem', '创建密文条目', '密码条目', 'web', true),
  'PATCH /api/v2/items/{itemId}': op('updateEncryptedItem', '更新条目元数据密文', '密码条目', 'web', true),
  'PUT /api/v2/items/{itemId}/secret': op('rotateEncryptedItemContent', '保存新的敏感内容密文版本', '密码条目', 'web', true),
  'DELETE /api/v2/items/{itemId}': op('deleteEncryptedItem', '删除密文条目', '密码条目', 'web', true),
  'POST /api/v2/items/{itemId}/content': op('getEncryptedItemContent', '读取条目敏感内容密文', '密码条目', 'web', true),
  'GET /api/v2/items/{itemId}/versions': op('listEncryptedItemVersions', '读取密文版本索引', '密码条目', 'web'),
  'GET /api/v2/vaults/{vaultId}/rekey-material': op('getVaultRekeyMaterial', '读取密钥轮换材料', '密码库', 'web'),
  'POST /api/v2/vaults/{vaultId}/rekey': op('commitVaultRekey', '提交完整密钥轮换', '密码库', 'web', true),
  'GET /api/v2/vaults/{vaultId}/migration': op('getLegacyMigration', '读取旧数据迁移状态', '迁移', 'web'),
  'POST /api/v2/vaults/{vaultId}/migration/start': op('startLegacyMigration', '冻结旧数据并开始迁移', '迁移', 'web', true),
  'POST /api/v2/vaults/{vaultId}/migration/export': op('claimLegacyMigrationExport', '领取隔离迁移密文包', '迁移', 'web', true),
  'POST /api/v2/vaults/{vaultId}/migration/target': op('setLegacyMigrationTarget', '提交迁移目标密钥', '迁移', 'web', true),
  'POST /api/v2/vaults/{vaultId}/migration/records': op('uploadLegacyMigrationRecords', '上传迁移后的密文记录', '迁移', 'web', true),
  'POST /api/v2/vaults/{vaultId}/migration/verify': op('verifyLegacyMigration', '验证迁移覆盖', '迁移', 'web', true),
  'POST /api/v2/vaults/{vaultId}/migration/cutover': op('cutoverLegacyMigration', '切换到零知识密文', '迁移', 'web', true),
  'POST /api/v2/vaults/{vaultId}/migration/rollback': op('rollbackLegacyMigration', '回滚迁移冻结', '迁移', 'web', true),
  'GET /api/v2/recovery/key': op('getActiveRecoveryKey', '读取当前企业恢复公钥', '企业恢复', 'web'),
  'GET /api/v2/recovery/keys': op('listRecoveryKeys', '读取企业恢复公钥轮换状态', '企业恢复', 'web'),
  'GET /api/v2/recovery/readiness': op('getRecoveryReadiness', '读取企业恢复管理员准备度', '企业恢复', 'web'),
  'POST /api/v2/recovery/key': op('registerRecoveryKey', '登记企业恢复公钥', '企业恢复', 'web', true),
  'POST /api/v2/recovery/keys/{keyId}/approve': op('approveRecoveryKey', '审批企业恢复公钥', '企业恢复', 'web', true),
  'GET /api/v2/recovery/keys/{keyId}/coverage': op('getRecoveryKeyCoverage', '读取企业恢复公钥逐库覆盖状态', '企业恢复', 'web'),
  'POST /api/v2/recovery/keys/{keyId}/vaults/{vaultId}/envelope': op('distributeRecoveryKey', '分发密码库恢复密钥', '企业恢复', 'web', true),
  'POST /api/v2/recovery/keys/{keyId}/activate': op('activateRecoveryKey', '启用企业恢复公钥', '企业恢复', 'web', true),
  'GET /api/v2/recovery/requests': op('listRecoveryRequests', '读取企业恢复请求', '企业恢复', 'web'),
  'GET /api/v2/recovery/candidates': op('listRecoveryCandidates', '读取需要管理员协助的个人密码库', '企业恢复', 'web'),
  'GET /api/v2/recovery/requests/{requestId}': op('getRecoveryRequest', '读取企业恢复请求', '企业恢复', 'web'),
  'GET /api/v2/recovery/requests/{requestId}/package': op('getRecoveryPackage', '下载离线恢复密文包', '企业恢复', 'web'),
  'POST /api/v2/recovery/requests': op('createRecoveryRequest', '发起企业恢复', '企业恢复', 'web', true),
  'POST /api/v2/recovery/requests/{requestId}/approve': op('approveRecoveryRequest', '审批企业恢复', '企业恢复', 'web', true),
  'POST /api/v2/recovery/requests/{requestId}/complete': op('completeRecoveryRequest', '确认企业恢复结果', '企业恢复', 'web', true),
  'POST /api/v2/extension/pairing': op('createEncryptedExtensionPairing', '创建零知识扩展配对码', '浏览器扩展', 'web', true),
  'POST /api/v2/extension/pairing/claim': op('claimEncryptedExtensionPairing', '提交扩展设备公钥', '浏览器扩展', 'public'),
  'GET /api/v2/extension/pairing/{enrollmentId}': op('pollEncryptedExtensionPairing', '轮询扩展配对结果', '浏览器扩展', 'public'),
  'GET /api/v2/extension/enrollments': op('listExtensionEnrollments', '读取扩展配对请求', '浏览器扩展', 'web'),
  'GET /api/v2/extension/enrollments/{enrollmentId}': op('getExtensionEnrollment', '读取扩展配对请求', '浏览器扩展', 'web'),
  'POST /api/v2/extension/enrollments/{enrollmentId}/approve': op('approveExtensionEnrollment', '批准扩展设备和密钥', '浏览器扩展', 'web', true),
  'POST /api/v2/extension/session/resume': op('resumeEncryptedExtensionSession', '为已授权扩展恢复在线会话', '浏览器扩展', 'web', true),
  'POST /api/v2/extension/unlock-challenges': op('createExtensionUnlockChallenge', '创建扩展解锁挑战', '浏览器扩展', 'extension'),
  'POST /api/v2/extension/crypto-unlock': op('completeExtensionUnlock', '完成扩展设备解锁', '浏览器扩展', 'extension'),
  'GET /api/v2/extension/bootstrap': op('getEncryptedExtensionBootstrap', '读取扩展密文快照', '浏览器扩展', 'extension'),
  'POST /api/v2/extension/items/{itemId}/content': op('getEncryptedExtensionContent', '读取扩展条目密文', '浏览器扩展', 'extension'),
  'DELETE /api/v2/extension/session': op('deleteEncryptedExtensionSession', '解除零知识扩展会话', '浏览器扩展', 'extension'),
  'GET /api/openapi.json': op('getOpenApiDocument', '读取 OpenAPI 契约', '运行状态', 'public'),
};

const TAGS = [
  ['认证与会话', '组织统一认证、会话状态和本地解锁挑战。'],
  ['同步', '只投递密文、版本和撤权状态的实时同步。'],
  ['用户组', '不持有组密钥的授权集合。'],
  ['密码库', '密码库密钥、成员和所有权生命周期。'],
  ['密码条目', '完整元数据和敏感内容均为客户端密文。'],
  ['审计', '服务端可验证的授权和密文操作记录。'],
  ['迁移', '隔离导出和客户端重加密迁移状态机。'],
  ['企业恢复', '双人审批和离线恢复材料流程。'],
  ['账户恢复', '丢失全部设备后的双管理员账户重置。'],
  ['浏览器扩展', '扩展设备配对、解锁和密文读取。'],
  ['运行状态', '健康检查和机器可读接口契约。'],
] as const;

export function buildOpenApiDocument(
  input: unknown,
  serverUrl: string,
  options: OpenApiBuildOptions = {},
): JsonObject {
  const document = JSON.parse(JSON.stringify(input)) as JsonObject;
  document.openapi = '3.0.3';
  document.info = {
    title: 'Mima API',
    description: '密码、Token、备注正文和完整条目元数据均由客户端加密；服务端只处理密文、公钥、签名和授权路由信息。',
    version: '0.2.0',
  };
  document.servers = [{ url: serverUrl.replace(/\/$/, ''), description: '生产环境' }];
  document.tags = TAGS.map(([name, description]) => ({ name, description }));

  const components = asObject(document.components);
  components.securitySchemes = {
    webSession: { type: 'apiKey', in: 'cookie', name: 'mima_sid', description: 'HttpOnly Web 会话 Cookie。' },
    extensionSession: { type: 'http', scheme: 'bearer', bearerFormat: 'opaque', description: '扩展设备绑定的不透明在线会话；显式撤销立即失效。' },
  };
  components.parameters = {
    ...asObject(components.parameters),
    csrfToken: {
      name: 'x-mima-csrf',
      in: 'header',
      required: true,
      description: 'Web 写请求的 CSRF token。',
      schema: { type: 'string' },
    },
  };
  document.components = components;

  const paths = asObject(document.paths);
  const seen = new Set<string>();
  for (const [path, pathValue] of Object.entries(paths)) {
    const pathItem = asObject(pathValue);
    for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
      if (!pathItem[method]) continue;
      const key = `${method.toUpperCase()} ${path}`;
      const metadata = OPERATIONS[key];
      if (!metadata) {
        if (options.pruneUndocumented) {
          delete pathItem[method];
          continue;
        }
        throw new Error(`OpenAPI operation metadata missing: ${key}`);
      }
      seen.add(key);
      const operation = asObject(pathItem[method]);
      operation.operationId = metadata.operationId;
      operation.summary = metadata.summary;
      operation.tags = [metadata.tag];
      operation.security = metadata.security === 'public'
        ? []
        : metadata.security === 'extension'
          ? [{ extensionSession: [] }]
          : [{ webSession: [] }];
      if (metadata.csrf) {
        const parameters = Array.isArray(operation.parameters) ? operation.parameters : [];
        if (!parameters.some(parameter => asObject(parameter).$ref === '#/components/parameters/csrfToken')) {
          operation.parameters = [...parameters, { $ref: '#/components/parameters/csrfToken' }];
        }
      }
      normalizeResponseDescriptions(operation);
      pathItem[method] = operation;
    }
    if (Object.keys(pathItem).length === 0) delete paths[path];
    else paths[path] = pathItem;
  }
  const missing = Object.keys(OPERATIONS).filter(key => !seen.has(key));
  if (missing.length) throw new Error(`Documented OpenAPI operations missing from runtime: ${missing.join(', ')}`);

  const events = asObject(asObject(paths['/api/v2/events']).get);
  events.responses = {
    ...asObject(events.responses),
    200: {
      description: 'SSE 密文事件流；事件不包含可读的条目元数据或敏感内容。',
      content: { 'text/event-stream': { schema: { type: 'string' } } },
    },
  };
  asObject(paths['/api/v2/events']).get = events;

  for (const path of [
    '/api/auth/oidc/start',
    '/api/auth/oidc/callback',
    '/api/auth/feishu/start',
    '/api/auth/feishu/callback',
  ]) {
    const method = path === '/api/auth/oidc/callback' ? 'post' : 'get';
    const operation = asObject(asObject(paths[path])[method]);
    const existingResponses = asObject(operation.responses);
    const nonSuccessResponses = Object.fromEntries(
      Object.entries(existingResponses).filter(([status]) => !/^2\d\d$/.test(status)),
    );
    if (path.endsWith('/callback')) {
      nonSuccessResponses['400'] = { description: '回调参数格式不正确或同时包含 code 与 error。' };
      nonSuccessResponses['404'] = { description: '当前未启用该认证方式。' };
    }
    operation.responses = {
      ...nonSuccessResponses,
      303: {
        description: path.endsWith('/start') ? '跳转到身份提供方。' : '认证完成后跳转回工作台。',
        headers: {
          Location: { schema: { type: 'string', format: 'uri' } },
          ...(path.endsWith('/callback') ? {
            'Cache-Control': {
              description: '禁止缓存认证回调响应。',
              schema: { type: 'string', enum: ['no-store'] },
            },
            'Referrer-Policy': {
              description: '禁止把认证回调地址作为 Referer 传播。',
              schema: { type: 'string', enum: ['no-referrer'] },
            },
          } : {}),
        },
      },
    };
    if (path === '/api/auth/oidc/callback') {
      operation.description = '只接受身份提供方的 form_post 表单；授权码和 state 不得放入回调 URL。';
    } else if (path === '/api/auth/feishu/callback') {
      operation.description = '必须携带 state，并且 code 与 error 恰好出现一个。飞书协议使用查询参数回调；边缘访问日志必须关闭查询串记录或完成脱敏。';
    }
    asObject(paths[path])[method] = operation;
  }

  const oidcCallback = asObject(asObject(paths['/api/auth/oidc/callback']).post);
  oidcCallback.requestBody = {
    required: true,
    content: {
      'application/x-www-form-urlencoded': {
        schema: {
          type: 'object',
          additionalProperties: false,
          required: ['state'],
          oneOf: [{ required: ['code'] }, { required: ['error'] }],
          properties: {
            code: { type: 'string', minLength: 1, maxLength: 8192 },
            error: { type: 'string', pattern: '^[A-Za-z0-9._~-]+$', maxLength: 128 },
            error_description: { type: 'string', maxLength: 2048 },
            error_uri: { type: 'string', format: 'uri', maxLength: 2048 },
            iss: { type: 'string', format: 'uri', maxLength: 2048 },
            scope: { type: 'string', maxLength: 2048 },
            session_state: { type: 'string', maxLength: 1024 },
            state: { type: 'string', minLength: 1, maxLength: 512 },
          },
        },
      },
    },
  };
  asObject(paths['/api/auth/oidc/callback']).post = oidcCallback;

  const createVaultOperation = asObject(asObject(paths['/api/v2/vaults']).post);
  const createVaultRequestBody = asObject(createVaultOperation.requestBody);
  const createVaultContent = asObject(createVaultRequestBody.content);
  const createVaultSchema = asObject(asObject(createVaultContent['application/json']).schema);
  markPropertyDeprecated(createVaultSchema, 'initialOwnerUserId');

  document.paths = paths;
  return document;
}

function op(
  operationId: string,
  summary: string,
  tag: string,
  security: OperationMetadata['security'],
  csrf = false,
): OperationMetadata {
  return { operationId, summary, tag, security, csrf };
}

function asObject(value: unknown): JsonObject {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : {};
}

function markPropertyDeprecated(schema: JsonObject, propertyName: string): void {
  const property = asObject(asObject(schema.properties)[propertyName]);
  if (Object.keys(property).length > 0) property.deprecated = true;
  for (const keyword of ['anyOf', 'oneOf', 'allOf'] as const) {
    const branches = schema[keyword];
    if (!Array.isArray(branches)) continue;
    for (const branch of branches) markPropertyDeprecated(asObject(branch), propertyName);
  }
}

function normalizeResponseDescriptions(operation: JsonObject): void {
  const responses = asObject(operation.responses);
  for (const [status, value] of Object.entries(responses)) {
    const response = asObject(value);
    if (response.description === 'Default Response') {
      response.description = /^2/.test(status)
        ? '请求成功。'
        : '请求校验、认证、授权、资源状态或版本冲突失败。';
    }
    responses[status] = response;
  }
  operation.responses = responses;
}
