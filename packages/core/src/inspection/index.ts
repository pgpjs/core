import { Key } from "../key/key.js";
import { readKey } from "../key/key-management.js";
import { SecretKeyPacket, PublicKeyPacket } from "../packet/index.js";

export interface KeyInfo {
  fingerprint: string;
  keyID: string;
  algorithm: string;
  encryptionAlgorithm?: string;
  version: number;
  createdAt: Date;
  expiresAt: Date | null;
  revoked: boolean;
  users: string[];
  subkeys: Array<{
    keyID: string;
    algorithm: string;
    flags: number[];
  }>;
}

export async function inspectKey(keyInput: Key | string | Uint8Array): Promise<KeyInfo> {
  const key: Key = keyInput instanceof Key
    ? keyInput
    : await readKey(typeof keyInput === "string" ? { armoredKey: keyInput } : { binaryKey: keyInput });

  const algo = key.getAlgorithmInfo();
  let encAlgo: string | undefined;

  for (const subkey of key.subkeys) {
    if (subkey.canEncrypt()) {
      encAlgo = subkey.getAlgorithmInfo().algorithm;
      break;
    }
  }

  const pk = key.primaryKey instanceof SecretKeyPacket ? key.primaryKey.publicKey : key.primaryKey;

  return {
    fingerprint: key.getFingerprint(),
    keyID: key.getKeyID(),
    algorithm: algo.algorithm,
    encryptionAlgorithm: encAlgo,
    version: pk.version,
    createdAt: key.getCreationTime(),
    expiresAt: key.getExpirationTime(),
    revoked: key.isRevoked(),
    users: key.getUserIDs(),
    subkeys: key.subkeys.map((sub) => ({
      keyID: sub.getKeyID(),
      algorithm: sub.getAlgorithmInfo().algorithm,
      flags: sub.getKeyFlags()
    }))
  };
}
