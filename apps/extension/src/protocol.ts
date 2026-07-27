import type {
  CipherBlob,
  CryptoDevice,
  EncryptedBootstrapResponse,
  EncryptedContentResponse,
  SessionUser,
} from '@mima/contracts';
import type {
  AccountBundle,
  ExtensionTrustedUnlockResponse,
  KdfProfile,
} from '@mima/e2ee';

export interface LocalWebUnlockRecord {
  version: 1;
  accountBundle: AccountBundle;
  encryptedPrivateBundle: CipherBlob;
}

export interface ExtSession {
  token: string;
  expiresAt: string;
  user: SessionUser;
  generation?: number;
  deviceId?: string;
}

export interface WorkbenchTrustedUnlockResult {
  response: ExtensionTrustedUnlockResponse;
  session: ExtSession;
}

export interface LocalDeviceRecord {
  version: 1;
  pairingOnly?: true;
  unlockFactorKind?: 'web-main-password';
  deviceId: string;
  name: string;
  platform: string;
  encryptionPublicKey: string;
  signingPublicKey: string;
  fingerprint: string;
  kdf: KdfProfile;
  encryptedPrivateBundle: CipherBlob;
  userId: string | null;
  certificate: string | null;
  certificateSignature: string | null;
  webUnlock?: LocalWebUnlockRecord;
}

export interface PendingEnrollment {
  enrollmentId: string;
  expiresAt: string;
  fingerprint: string;
  sealedApproval?: string;
}

export interface PairingClaimRequest {
  code: string;
  device: {
    id: string;
    deviceType: 'extension';
    encryptionPublicKey: string;
    signingPublicKey: string;
    joinChannelPublicKey: string;
    fingerprint: string;
  };
  existingDeviceProof?: string;
}

export interface PairingClaimResponse extends PendingEnrollment {
  status: 'pending' | 'approved';
  pollToken: string;
  sealedApproval?: string;
}

export interface PairingStatusResponse extends PendingEnrollment {
  status: 'pending' | 'approved' | 'expired' | 'rejected';
  sealedApproval?: string;
}

export interface PairingApproval {
  session: ExtSession;
  device: CryptoDevice;
  profileSigningPublicKey: string;
  bootstrap?: ExtensionBootstrap;
}

export interface ExtensionBootstrap extends EncryptedBootstrapResponse {
  contents?: ExtensionContentResponse[];
}

export interface ExtensionContentRequest {
  purpose: 'copy' | 'fill';
  secretVersion?: number;
  deviceId: string;
  intentSignature: string;
}

export type ExtensionContentResponse = EncryptedContentResponse;

export interface UnlockChallengeResponse {
  id: string;
  challenge: string;
  expiresAt: string;
}

export interface CiphertextCache {
  version: 1;
  bootstrap: ExtensionBootstrap;
  contents: Record<string, ExtensionContentResponse>;
  updatedAt: string;
}

export interface DecryptedExtensionItem {
  id: string;
  vaultId: string;
  kind: 'login' | 'api_token' | 'secure_note';
  title: string;
  username: string | null;
  origin: string | null;
  loginUrl?: string | null;
  loginUrls?: string[];
  description?: string | null;
  linkedLoginItemId?: string | null;
  tags: string[];
  favorite: boolean;
  sensitivity: 'low' | 'medium' | 'high';
  secretState: 'present' | 'absent';
  version: number;
  secretVersion: number;
  keyEpoch: number;
}
