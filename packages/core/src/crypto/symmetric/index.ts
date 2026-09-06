import { unsafe } from "@noble/ciphers/aes";
import { SymmetricKeyAlgorithm } from "../../types/enums.js";
import { PGPAlgorithmError } from "../../errors/index.js";

export function getCipherKeySize(algorithm: SymmetricKeyAlgorithm): number {
  switch (algorithm) {
    case SymmetricKeyAlgorithm.AES128:
      return 16;
    case SymmetricKeyAlgorithm.AES192:
      return 24;
    case SymmetricKeyAlgorithm.AES256:
      return 32;
    case SymmetricKeyAlgorithm.TripleDES:
      return 24;
    case SymmetricKeyAlgorithm.CAST5:
    case SymmetricKeyAlgorithm.Blowfish:
      return 16;
    default:
      throw new PGPAlgorithmError(`Unsupported symmetric algorithm: ${algorithm}`);
  }
}

export function getCipherBlockSize(algorithm: SymmetricKeyAlgorithm): number {
  switch (algorithm) {
    case SymmetricKeyAlgorithm.AES128:
    case SymmetricKeyAlgorithm.AES192:
    case SymmetricKeyAlgorithm.AES256:
      return 16;
    case SymmetricKeyAlgorithm.TripleDES:
    case SymmetricKeyAlgorithm.CAST5:
    case SymmetricKeyAlgorithm.Blowfish:
      return 8;
    default:
      throw new PGPAlgorithmError(`Unsupported symmetric algorithm: ${algorithm}`);
  }
}

/**
 * Returns a raw single-block encrypt function E(block).
 */
export function createBlockEncryptor(
  algorithm: SymmetricKeyAlgorithm,
  key: Uint8Array
): (block: Uint8Array) => Uint8Array {
  const keySize = getCipherKeySize(algorithm);
  if (key.length !== keySize) {
    throw new PGPAlgorithmError(
      `Invalid key length for algorithm ${algorithm}: expected ${keySize}, got ${key.length}`
    );
  }

  switch (algorithm) {
    case SymmetricKeyAlgorithm.AES128:
    case SymmetricKeyAlgorithm.AES192:
    case SymmetricKeyAlgorithm.AES256: {
      const expandedKey = unsafe.expandKeyLE(key);
      return (block: Uint8Array) => {
        const copy = new Uint8Array(16);
        copy.set(block.subarray(0, 16));
        unsafe.encryptBlock(expandedKey, copy);
        return copy;
      };
    }
    default:
      throw new PGPAlgorithmError(`Unsupported block cipher for symmetric encryption: ${algorithm}`);
  }
}

/**
 * Returns a raw single-block decrypt function D(block).
 */
export function createBlockDecryptor(
  algorithm: SymmetricKeyAlgorithm,
  key: Uint8Array
): (block: Uint8Array) => Uint8Array {
  const keySize = getCipherKeySize(algorithm);
  if (key.length !== keySize) {
    throw new PGPAlgorithmError(
      `Invalid key length for algorithm ${algorithm}: expected ${keySize}, got ${key.length}`
    );
  }

  switch (algorithm) {
    case SymmetricKeyAlgorithm.AES128:
    case SymmetricKeyAlgorithm.AES192:
    case SymmetricKeyAlgorithm.AES256: {
      const expandedKey = unsafe.expandKeyLE(key);
      return (block: Uint8Array) => {
        const copy = new Uint8Array(16);
        copy.set(block.subarray(0, 16));
        unsafe.decryptBlock(expandedKey, copy);
        return copy;
      };
    }
    default:
      throw new PGPAlgorithmError(`Unsupported block cipher for symmetric decryption: ${algorithm}`);
  }
}
