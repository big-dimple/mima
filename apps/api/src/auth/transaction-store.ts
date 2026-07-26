import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto';
import { eq, lt } from 'drizzle-orm';
import type { MasterKeyProvider } from '@mima/crypto';
import type { Db } from '../db/client.ts';
import { oidcTransactions } from '../db/schema.ts';

export interface OidcTransactionPayload {
  purpose: 'login' | 'reauth';
  codeVerifier: string;
  nonce: string;
  sessionId: string | null;
  userId: string | null;
  previousAuthenticatedAt: string | null;
  browserBindingHash: string;
}

export interface ConsumedOidcTransaction extends OidcTransactionPayload {
  startedAt: Date;
}

const TRANSACTION_TTL_MS = 5 * 60 * 1000;
const INFO = Buffer.from('mima.oidc-transaction.v1', 'utf8');

export class OidcTransactionStore {
  constructor(
    private readonly db: Db,
    private readonly keys: MasterKeyProvider,
  ) {}

  static stateHash(state: string): string {
    return createHash('sha256').update(state).digest('hex');
  }

  async create(state: string, payload: OidcTransactionPayload): Promise<void> {
    const stateHash = OidcTransactionStore.stateHash(state);
    const keyVersion = this.keys.activeVersion();
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.deriveKey(keyVersion), iv);
    cipher.setAAD(this.aad(stateHash, payload.purpose));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(payload), 'utf8'),
      cipher.final(),
    ]);
    await this.db.delete(oidcTransactions).where(lt(oidcTransactions.expiresAt, new Date()));
    await this.db.insert(oidcTransactions).values({
      stateHash,
      purpose: payload.purpose,
      ciphertext,
      iv,
      authTag: cipher.getAuthTag(),
      keyVersion,
      expiresAt: new Date(Date.now() + TRANSACTION_TTL_MS),
    });
  }

  async consume(state: string): Promise<ConsumedOidcTransaction | null> {
    const stateHash = OidcTransactionStore.stateHash(state);
    const rows = await this.db
      .delete(oidcTransactions)
      .where(eq(oidcTransactions.stateHash, stateHash))
      .returning();
    const row = rows[0];
    if (!row || row.expiresAt.getTime() < Date.now()) return null;
    const decipher = createDecipheriv('aes-256-gcm', this.deriveKey(row.keyVersion), row.iv);
    decipher.setAAD(this.aad(stateHash, row.purpose));
    decipher.setAuthTag(row.authTag);
    const plaintext = Buffer.concat([decipher.update(row.ciphertext), decipher.final()]).toString('utf8');
    const parsed = JSON.parse(plaintext) as OidcTransactionPayload;
    if (parsed.purpose !== row.purpose) throw new Error('OIDC transaction purpose mismatch');
    return { ...parsed, startedAt: row.createdAt };
  }

  private deriveKey(version: string): Buffer {
    return Buffer.from(
      hkdfSync('sha256', this.keys.getKey(version), Buffer.alloc(0), INFO, 32),
    );
  }

  private aad(stateHash: string, purpose: string): Buffer {
    return Buffer.from(`mima.oidc-transaction.v1|${stateHash}|${purpose}`, 'utf8');
  }
}
