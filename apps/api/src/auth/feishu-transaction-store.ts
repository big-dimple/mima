import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import { eq, lt } from 'drizzle-orm';
import type { MasterKeyProvider } from '@mima/crypto';
import type { Db } from '../db/client.ts';
import { authTransactions } from '../db/schema.ts';

interface FeishuTransactionPayload {
  browserBindingHash: string;
}

export interface ConsumedFeishuTransaction extends FeishuTransactionPayload {
  startedAt: Date;
}

const TRANSACTION_TTL_MS = 5 * 60 * 1000;
const INFO = Buffer.from('mima.feishu-transaction.v1', 'utf8');

export class FeishuTransactionStore {
  constructor(
    private readonly db: Db,
    private readonly keys: MasterKeyProvider,
  ) {}

  static stateHash(state: string): string {
    return createHash('sha256').update(state).digest('hex');
  }

  async create(state: string, payload: FeishuTransactionPayload): Promise<void> {
    const stateHash = FeishuTransactionStore.stateHash(state);
    const keyVersion = this.keys.activeVersion();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.deriveKey(keyVersion), iv);
    cipher.setAAD(this.aad(stateHash));
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
    await this.db.delete(authTransactions).where(lt(authTransactions.expiresAt, new Date()));
    await this.db.insert(authTransactions).values({
      stateHash,
      provider: 'feishu',
      purpose: 'login',
      ciphertext,
      iv,
      authTag: cipher.getAuthTag(),
      keyVersion,
      expiresAt: new Date(Date.now() + TRANSACTION_TTL_MS),
    });
  }

  async consume(state: string): Promise<ConsumedFeishuTransaction | null> {
    const stateHash = FeishuTransactionStore.stateHash(state);
    const row = (
      await this.db
        .delete(authTransactions)
        .where(eq(authTransactions.stateHash, stateHash))
        .returning()
    )[0];
    if (!row || row.provider !== 'feishu' || row.purpose !== 'login' || row.expiresAt.getTime() < Date.now()) {
      return null;
    }
    const decipher = createDecipheriv('aes-256-gcm', this.deriveKey(row.keyVersion), row.iv);
    decipher.setAAD(this.aad(stateHash));
    decipher.setAuthTag(row.authTag);
    const plaintext = Buffer.concat([decipher.update(row.ciphertext), decipher.final()]).toString('utf8');
    return { ...(JSON.parse(plaintext) as FeishuTransactionPayload), startedAt: row.createdAt };
  }

  private deriveKey(version: string): Buffer {
    return Buffer.from(hkdfSync('sha256', this.keys.getKey(version), Buffer.alloc(0), INFO, 32));
  }

  private aad(stateHash: string): Buffer {
    return Buffer.from(`mima.feishu-transaction.v1|${stateHash}|login`, 'utf8');
  }
}
