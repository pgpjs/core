import { HashAlgorithm } from "../../types/enums.js";
import { getHasher } from "../hash/index.js";
import { utf8ToBytes } from "../../utils/bytes.js";

export function deriveSimpleS2K(
  passphrase: string,
  keySize: number,
  hashAlgorithm: HashAlgorithm
): Uint8Array {
  const passBytes = utf8ToBytes(passphrase);
  const hasher = getHasher(hashAlgorithm);
  const key = new Uint8Array(keySize);
  let derived = 0;
  let preloadCount = 0;

  while (derived < keySize) {
    const h = hasher.create();
    for (let i = 0; i < preloadCount; i++) {
      h.update(new Uint8Array([0]));
    }
    h.update(passBytes);
    const digest = h.digest();
    const copyLen = Math.min(digest.length, keySize - derived);
    key.set(digest.subarray(0, copyLen), derived);
    derived += copyLen;
    preloadCount++;
  }

  return key;
}
