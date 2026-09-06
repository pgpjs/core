import { argon2id } from "@noble/hashes/argon2";
import { utf8ToBytes } from "../../utils/bytes.js";

/**
 * RFC 9580 Argon2 S2K (Type 4).
 */
export function deriveArgon2S2K(
  passphrase: string,
  salt: Uint8Array,
  keySize: number,
  options: {
    passes?: number;
    memoryExponent?: number;
    parallelism?: number;
  } = {}
): Uint8Array {
  const passes = options.passes ?? 3;
  const memoryExponent = options.memoryExponent ?? 16;
  const parallelism = options.parallelism ?? 4;
  const memoryKiB = 1 << memoryExponent;

  return argon2id(utf8ToBytes(passphrase), salt, {
    t: passes,
    m: memoryKiB,
    p: parallelism,
    dkLen: keySize
  });
}
