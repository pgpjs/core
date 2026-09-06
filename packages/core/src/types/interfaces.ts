import {
  CompressionAlgorithm,
  HashAlgorithm,
  KeyFlag,
  PublicKeyAlgorithm,
  SymmetricKeyAlgorithm
} from './enums.js';

export interface UserID {
  name?: string;
  email?: string;
  comment?: string;
}

export interface SubkeyOptions {
  type?: 'rsa' | 'ecc';
  curve?: 'ed25519' | 'curve25519' | 'p256' | 'p384' | 'p521';
  rsaBits?: 2048 | 3072 | 4096;
  flags?: KeyFlag[];
  keyExpirationTime?: number | Date;
}

export interface GenerateKeyPairOptions {
  type?: 'rsa' | 'ecc';
  curve?: 'ed25519' | 'curve25519' | 'p256' | 'p384' | 'p521';
  rsaBits?: 2048 | 3072 | 4096;
  userIDs: (UserID | string)[];
  passphrase?: string;
  keyExpirationTime?: number | Date;
  subkeys?: SubkeyOptions[];
}

export interface AlgorithmInfo {
  algorithm: string;
  bits?: number;
  curve?: string;
}

export interface VerifiedSignature {
  keyID: string;
  fingerprint?: string;
  valid: boolean;
  verified: Promise<boolean>;
  signature: any;
  error?: Error;
}

export interface DecryptResult {
  data: Uint8Array;
  text?: string;
  filename?: string;
  date?: Date;
  signatures: VerifiedSignature[];
  encrypted: boolean;
}

export interface VerifyResult {
  data: Uint8Array;
  text?: string;
  signatures: VerifiedSignature[];
}

export interface EncryptOptions {
  message: any;
  encryptionKeys?: any | any[];
  passwords?: string | string[];
  signingKeys?: any | any[];
  format?: 'armored' | 'binary';
  compression?: CompressionAlgorithm;
  symmetricAlgorithm?: SymmetricKeyAlgorithm;
}

export interface DecryptOptions {
  message: any;
  decryptionKeys?: any | any[];
  passwords?: string | string[];
  verificationKeys?: any | any[];
}

export interface SignOptions {
  message: any;
  signingKeys: any | any[];
  detached?: boolean;
  format?: 'armored' | 'binary';
  hashAlgorithm?: HashAlgorithm;
}

export interface VerifyOptions {
  message: any;
  verificationKeys: any | any[];
  signature?: any | string | Uint8Array;
}
