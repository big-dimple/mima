import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { EncryptedSyncEventSchema } from '@mima/contracts';
import { Parser } from '@asyncapi/parser';
import { zodToJsonSchema } from 'zod-to-json-schema';

const converted = zodToJsonSchema(EncryptedSyncEventSchema, {
  name: 'EncryptedSyncEvent',
  target: 'jsonSchema7',
  $refStrategy: 'root',
}) as Record<string, unknown>;
const definitions = (converted.definitions ?? {}) as Record<string, unknown>;
const schemas = rewriteReferences(definitions) as Record<string, unknown>;

const document = {
  asyncapi: '2.6.0',
  defaultContentType: 'application/json',
  info: {
    title: 'Mima 实时同步事件 API',
    version: '0.2.0',
    description: '工作台通过 SSE 接收的零知识密文事件。事件不携带可读的密码库名称、条目元数据、密码、Token 或备注正文。',
  },
  tags: [
    {
      name: '密文同步',
      description: '只传递密文、版本、授权变化和同步游标。',
    },
  ],
  servers: {
    production: {
      url: 'mima.example.com',
      protocol: 'https',
      description: '生产环境 SSE 入口',
      security: [{ webSession: [] }],
    },
  },
  channels: {
    '/api/v2/events': {
      description: '按 cursor 回放密文事件后切换为实时投递，sync.ready 表示客户端可进入在线状态。',
      subscribe: {
        operationId: 'streamEncryptedSyncEvents',
        summary: '订阅密码库密文、版本和撤权变化',
        tags: [{ name: '密文同步' }],
        message: { $ref: '#/components/messages/EncryptedSyncEvent' },
      },
    },
  },
  components: {
    securitySchemes: {
      webSession: {
        type: 'httpApiKey',
        in: 'cookie',
        name: 'mima_sid',
        description: 'HttpOnly Web 会话 Cookie。',
      },
    },
    messages: {
      EncryptedSyncEvent: {
        messageId: 'encryptedSyncEvent',
        name: 'EncryptedSyncEvent',
        title: '零知识密文同步事件',
        contentType: 'application/json',
        payload: { $ref: '#/components/schemas/EncryptedSyncEvent' },
      },
    },
    schemas,
  },
};

const parsed = await new Parser().parse(document);
const fatalDiagnostics = parsed.diagnostics.filter((diagnostic) => diagnostic.severity === 0);
if (!parsed.document || fatalDiagnostics.length > 0) {
  const detail = fatalDiagnostics
    .slice(0, 12)
    .map((diagnostic) => `${diagnostic.path.join('.')} ${diagnostic.message}`.trim())
    .join('\n');
  throw new Error(`Generated AsyncAPI is invalid${detail ? `:\n${detail}` : ''}`);
}

const out = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'openapi', 'asyncapi.json');
mkdirSync(dirname(out), { recursive: true });
const content = JSON.stringify(document, null, 2) + '\n';
if (process.argv.includes('--check')) {
  if (readFileSync(out, 'utf8') !== content) throw new Error('AsyncAPI contract is stale; run asyncapi:generate');
  console.log(`AsyncAPI is current: ${out}`);
} else {
  writeFileSync(out, content);
  console.log(`AsyncAPI written to ${out}`);
}

function rewriteReferences(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(rewriteReferences);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, item]) => [
      key,
      key === '$ref' && typeof item === 'string'
        ? item.replace('#/definitions/', '#/components/schemas/')
        : rewriteReferences(item),
    ]),
  );
}
