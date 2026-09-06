import { ed25519 } from "@noble/curves/ed25519";
import { concatBytes, hexToBytes } from "../../../utils/bytes.js";

export const ED25519_OID = hexToBytes("2b06010401da470f01"); // 1.3.6.1.4.1.11591.15.1

export interface Ed25519KeyPair {
  publicKey: Uint8Array; // 33 bytes: 0x40 prefix + 32-byte point
  privateKey: Uint8Array; // 32-byte scalar
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const rawPub = ed25519.getPublicKey(privateKey);
  const publicKey = concatBytes(new Uint8Array([0x40]), rawPub);
  return { publicKey, privateKey };
}

export function signEd25519(privateKey: Uint8Array, messageDigest: Uint8Array): { r: Uint8Array; s: Uint8Array } {
  const rawSig = ed25519.sign(messageDigest, privateKey);
  return {
    r: rawSig.subarray(0, 32),
    s: rawSig.subarray(32, 64)
  };
}

export function verifyEd25519(publicKey: Uint8Array, messageDigest: Uint8Array, r: Uint8Array, s: Uint8Array): boolean {
  const point = publicKey.length === 33 && publicKey[0] === 0x40 ? publicKey.subarray(1) : publicKey;
  const rawSig = concatBytes(r, s);
  try {
    return ed25519.verify(rawSig, messageDigest, point);
  } catch {
    return false;
  }
}
