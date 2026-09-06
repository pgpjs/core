import { HashAlgorithm, SymmetricKeyAlgorithm } from "../types/enums.js";
import { PGPAlgorithmError, PGPVerificationError } from "../errors/index.js";
import { Key } from "../key/key.js";

export interface SecurityPolicy {
  allowedEncryption?: SymmetricKeyAlgorithm[];
  allowedHash?: HashAlgorithm[];
  allowLegacyAlgorithms?: boolean;
  requireSignature?: boolean;
  requireValidKey?: boolean;
  rejectExpiredKeys?: boolean;
  rejectRevokedKeys?: boolean;
  minimumStrength?: "legacy" | "standard" | "modern";
  requireAEAD?: boolean;
}

export const DEFAULT_SECURITY_POLICY: SecurityPolicy = {
  allowedEncryption: [
    SymmetricKeyAlgorithm.AES256,
    SymmetricKeyAlgorithm.AES192,
    SymmetricKeyAlgorithm.AES128
  ],
  allowedHash: [
    HashAlgorithm.SHA256,
    HashAlgorithm.SHA384,
    HashAlgorithm.SHA512
  ],
  allowLegacyAlgorithms: false,
  requireSignature: false,
  requireValidKey: true,
  rejectExpiredKeys: true,
  rejectRevokedKeys: true,
  minimumStrength: "modern",
  requireAEAD: false
};

export function validatePolicyKey(key: Key, policy: SecurityPolicy = DEFAULT_SECURITY_POLICY): void {
  if (policy.rejectRevokedKeys && key.isRevoked()) {
    throw new PGPVerificationError("Key is revoked according to security policy");
  }

  if (policy.rejectExpiredKeys && key.isExpired()) {
    throw new PGPVerificationError("Key is expired according to security policy");
  }

  if (!policy.allowLegacyAlgorithms) {
    const algo = key.getAlgorithmInfo();
    if (algo.algorithm === "RSA" && algo.bits && algo.bits < 2048) {
      throw new PGPAlgorithmError("RSA key length < 2048 rejected by security policy");
    }
  }
}
