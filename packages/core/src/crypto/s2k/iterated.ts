import { HashAlgorithm } from "../../types/enums.js";
import { getHasher } from "../hash/index.js";
import { utf8ToBytes } from "../../utils/bytes.js";

export function decodeS2KCount(c: number): number {
  return (16 + (c & 15)) << ((c >> 4) + 6);
}

export function encodeS2KCount(target: number): number {
  if (target <= 1024) return 0;
  for (let c = 0; c < 256; c++) {
    if (decodeS2KCount(c) >= target) {
      return c;
    }
  }
  return 255;
}

export function deriveIteratedS2K(
  passphrase: string,
  salt: Uint8Array,
  count: number,
  keySize: number,
  hashAlgorithm: HashAlgorithm
): Uint8Array {
  const passBytes = utf8ToBytes(passphrase);
  const hasher = getHasher(hashAlgorithm);
  const key = new Uint8Array(keySize);
  let derived = 0;
  let preloadCount = 0;

  const combined = new Uint8Array(salt.length + passBytes.length);
  combined.set(salt, 0);
  combined.set(passBytes, salt.length);

  while (derived < keySize) {
    const h = hasher.create();
    for (let i = 0; i < preloadCount; i++) {
      h.update(new Uint8Array([0]));
    }

    let remaining = count;
    while (remaining > 0) {
      if (remaining >= combined.length) {
        h.update(combined);
        remaining -= combined.length;
      } else {
        h.update(combined.subarray(0, remaining));
        remaining = 0;
      }
    }

    const digest = h.digest();
    const copyLen = Math.min(digest.length, keySize - derived);
    key.set(digest.subarray(0, copyLen), derived);
    derived += copyLen;
    preloadCount++;
  }

  return key;
}
