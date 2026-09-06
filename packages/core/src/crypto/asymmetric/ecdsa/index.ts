import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { aeskw } from "@noble/ciphers/aes";
import { HashAlgorithm, SymmetricKeyAlgorithm } from "../../../types/enums.js";
import { PGPAlgorithmError, PGPDecryptionError, PGPEncryptionError, PGPSignatureError } from "../../../errors/index.js";
import { concatBytes, hexToBytes } from "../../../utils/bytes.js";
import { hash } from "../../hash/index.js";
import { getCipherKeySize } from "../../symmetric/index.js";

export const NIST_OIDS: Record<string, Uint8Array> = {
  p256: hexToBytes("2a8648ce3d030107"), // 1.2.840.10045.3.1.7
  p384: hexToBytes("2b81040022"), // 1.3.132.0.34
  p521: hexToBytes("2b81040023") // 1.3.132.0.35
};

export function getNISTCurve(curve: "p256" | "p384" | "p521") {
  switch (curve) {
    case "p256": return p256;
    case "p384": return p384;
    case "p521": return p521;
    default: throw new PGPAlgorithmError(`Unsupported NIST curve: ${curve}`);
  }
}

export function generateNISTKeyPair(curve: "p256" | "p384" | "p521"): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const c = getNISTCurve(curve);
  const privateKey = c.utils.randomPrivateKey();
  const publicKey = c.getPublicKey(privateKey, false); // uncompressed 0x04 format
  return { publicKey, privateKey };
}

export function signECDSA(
  curve: "p256" | "p384" | "p521",
  privateKey: Uint8Array,
  messageDigest: Uint8Array
): { r: Uint8Array; s: Uint8Array } {
  const c = getNISTCurve(curve);
  const sig = c.sign(messageDigest, privateKey);
  const nBytes = Math.ceil(c.CURVE.n.toString(2).length / 8);
  const rBytes = hexToBytes(sig.r.toString(16).padStart(nBytes * 2, "0"));
  const sBytes = hexToBytes(sig.s.toString(16).padStart(nBytes * 2, "0"));
  return { r: rBytes, s: sBytes };
}

export function verifyECDSA(
  curve: "p256" | "p384" | "p521",
  publicKey: Uint8Array,
  messageDigest: Uint8Array,
  r: Uint8Array,
  s: Uint8Array
): boolean {
  const c = getNISTCurve(curve);
  try {
    const rBig = BigInt("0x" + Array.from(r).map(b => b.toString(16).padStart(2, "0")).join(""));
    const sBig = BigInt("0x" + Array.from(s).map(b => b.toString(16).padStart(2, "0")).join(""));
    return (c as any).verify({ r: rBig, s: sBig }, messageDigest, publicKey);
  } catch {
    return false;
  }
}
