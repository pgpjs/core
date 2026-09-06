import { generateEd25519KeyPair, signEd25519, verifyEd25519, ED25519_OID } from "./ed25519/index.js";
import { generateX25519KeyPair, encryptX25519ECDH, decryptX25519ECDH, X25519_OID } from "./x25519/index.js";
import { generateNISTKeyPair, signECDSA, verifyECDSA, NIST_OIDS, getNISTCurve } from "./ecdsa/index.js";
import { HashAlgorithm, PublicKeyAlgorithm, SymmetricKeyAlgorithm } from "../../types/enums.js";
import { PGPAlgorithmError } from "../../errors/index.js";

export * from "./rsa/index.js";
export * from "./ed25519/index.js";
export * from "./x25519/index.js";
export * from "./ecdsa/index.js";

export const CURVE_OIDS: Record<string, Uint8Array> = {
  ed25519: ED25519_OID,
  curve25519: X25519_OID,
  p256: NIST_OIDS.p256,
  p384: NIST_OIDS.p384,
  p521: NIST_OIDS.p521
};

export function getCurveNameByOID(oid: Uint8Array): string {
  const hex = Array.from(oid).map((b) => b.toString(16).padStart(2, "0")).join("");
  for (const [name, curveOID] of Object.entries(CURVE_OIDS)) {
    const oHex = Array.from(curveOID).map((b) => b.toString(16).padStart(2, "0")).join("");
    if (hex === oHex) {
      return name;
    }
  }
  throw new PGPAlgorithmError(`Unknown curve OID: ${hex}`);
}

export interface ECCKeyPair {
  curve: "ed25519" | "curve25519" | "p256" | "p384" | "p521";
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateECCKeyPair(curve: "ed25519" | "curve25519" | "p256" | "p384" | "p521" = "ed25519"): ECCKeyPair {
  switch (curve) {
    case "ed25519": {
      const { publicKey, privateKey } = generateEd25519KeyPair();
      return { curve, publicKey, privateKey };
    }
    case "curve25519": {
      const { publicKey, privateKey } = generateX25519KeyPair();
      return { curve, publicKey, privateKey };
    }
    case "p256":
    case "p384":
    case "p521": {
      const { publicKey, privateKey } = generateNISTKeyPair(curve);
      return { curve, publicKey, privateKey };
    }
    default:
      throw new PGPAlgorithmError(`Unsupported curve: ${curve}`);
  }
}

export function signECC(
  curve: "ed25519" | "p256" | "p384" | "p521" | string,
  privateKey: Uint8Array,
  messageDigest: Uint8Array
): { r: Uint8Array; s: Uint8Array } {
  if (curve === "ed25519") {
    return signEd25519(privateKey, messageDigest);
  }
  if (curve === "p256" || curve === "p384" || curve === "p521") {
    return signECDSA(curve, privateKey, messageDigest);
  }
  throw new PGPAlgorithmError(`Unsupported ECC signing curve: ${curve}`);
}

export function verifyECC(
  curve: "ed25519" | "p256" | "p384" | "p521" | string,
  publicKey: Uint8Array,
  messageDigest: Uint8Array,
  r: Uint8Array,
  s: Uint8Array
): boolean {
  if (curve === "ed25519") {
    return verifyEd25519(publicKey, messageDigest, r, s);
  }
  if (curve === "p256" || curve === "p384" || curve === "p521") {
    return verifyECDSA(curve, publicKey, messageDigest, r, s);
  }
  return false;
}

export function encryptECDH(
  curve: "curve25519" | "p256" | "p384" | "p521" | string,
  recipientPublicKey: Uint8Array,
  recipientFingerprint: Uint8Array,
  sessionKey: Uint8Array,
  symmetricAlgorithm: SymmetricKeyAlgorithm,
  hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256,
  kdfSymmetricAlgorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES128
): { ephemeralPublicKey: Uint8Array; wrappedKey: Uint8Array } {
  if (curve === "curve25519") {
    return encryptX25519ECDH(
      recipientPublicKey,
      recipientFingerprint,
      sessionKey,
      symmetricAlgorithm,
      hashAlgorithm,
      kdfSymmetricAlgorithm
    );
  }
  throw new PGPAlgorithmError(`NIST ECDH encryption not implemented yet for curve ${curve}`);
}

export function decryptECDH(
  curve: "curve25519" | "p256" | "p384" | "p521" | string,
  recipientPrivateKey: Uint8Array,
  recipientFingerprint: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  wrappedKey: Uint8Array,
  hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256,
  kdfSymmetricAlgorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES128
): { sessionKey: Uint8Array; symmetricAlgorithm: SymmetricKeyAlgorithm } {
  if (curve === "curve25519") {
    return decryptX25519ECDH(
      recipientPrivateKey,
      recipientFingerprint,
      ephemeralPublicKey,
      wrappedKey,
      hashAlgorithm,
      kdfSymmetricAlgorithm
    );
  }
  throw new PGPAlgorithmError(`NIST ECDH decryption not implemented yet for curve ${curve}`);
}
