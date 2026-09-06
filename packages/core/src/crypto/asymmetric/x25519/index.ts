import { x25519 } from "@noble/curves/ed25519";
import { aeskw } from "@noble/ciphers/aes";
import { HashAlgorithm, SymmetricKeyAlgorithm } from "../../../types/enums.js";
import { PGPDecryptionError, PGPEncryptionError } from "../../../errors/index.js";
import { concatBytes, hexToBytes, writeUint16BE } from "../../../utils/bytes.js";
import { hash } from "../../hash/index.js";
import { getCipherKeySize } from "../../symmetric/index.js";

export const X25519_OID = hexToBytes("2b060104019755010501"); // 1.3.6.1.4.1.3029.1.5.1

export interface X25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export function generateX25519KeyPair(): X25519KeyPair {
  const privateKey = x25519.utils.randomPrivateKey();
  const rawPub = x25519.getPublicKey(privateKey);
  const publicKey = concatBytes(new Uint8Array([0x40]), rawPub);
  return { publicKey, privateKey };
}

export function kdfX963(
  sharedSecret: Uint8Array,
  keySize: number,
  hashAlgorithm: HashAlgorithm,
  paramBytes: Uint8Array
): Uint8Array {
  const counter = new Uint8Array([0x00, 0x00, 0x00, 0x01]);
  const input = concatBytes(sharedSecret, counter, paramBytes);
  const digest = hash(hashAlgorithm, input);
  return digest.subarray(0, keySize);
}

export function encryptX25519ECDH(
  recipientPublicKey: Uint8Array,
  recipientFingerprint: Uint8Array,
  sessionKey: Uint8Array,
  symmetricAlgorithm: SymmetricKeyAlgorithm,
  hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256,
  kdfSymmetricAlgorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES128
): { ephemeralPublicKey: Uint8Array; wrappedKey: Uint8Array } {
  const ephemeralPriv = x25519.utils.randomPrivateKey();
  const rawEphemeralPub = x25519.getPublicKey(ephemeralPriv);
  const ephemeralPublicKey = concatBytes(new Uint8Array([0x40]), rawEphemeralPub);

  const recipientPoint = recipientPublicKey.length === 33 && recipientPublicKey[0] === 0x40
    ? recipientPublicKey.subarray(1)
    : recipientPublicKey;

  let sharedSecret: Uint8Array;
  try {
    sharedSecret = x25519.getSharedSecret(ephemeralPriv, recipientPoint);
  } catch (err: any) {
    throw new PGPEncryptionError(`X25519 ECDH shared secret computation failed: ${err.message}`);
  }

  const kekSize = getCipherKeySize(kdfSymmetricAlgorithm);
  const paramBytes = concatBytes(
    new Uint8Array([X25519_OID.length]),
    X25519_OID,
    new Uint8Array([18]), // PublicKeyAlgorithm.ECDH
    new Uint8Array([3, 1, hashAlgorithm, kdfSymmetricAlgorithm]),
    new Uint8Array([0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x20, 0x20, 0x20, 0x20]),
    recipientFingerprint
  );

  const kek = kdfX963(sharedSecret, kekSize, hashAlgorithm, paramBytes);

  const keyPayload = concatBytes(new Uint8Array([symmetricAlgorithm]), sessionKey);
  const padLen = 8 - (keyPayload.length % 8);
  const paddedKey = new Uint8Array(keyPayload.length + padLen);
  paddedKey.set(keyPayload, 0);
  for (let i = keyPayload.length; i < paddedKey.length; i++) {
    paddedKey[i] = padLen;
  }

  const wrappedKey = aeskw(kek).encrypt(paddedKey);
  return { ephemeralPublicKey, wrappedKey };
}

export function decryptX25519ECDH(
  recipientPrivateKey: Uint8Array,
  recipientFingerprint: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  wrappedKey: Uint8Array,
  hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256,
  kdfSymmetricAlgorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES128
): { sessionKey: Uint8Array; symmetricAlgorithm: SymmetricKeyAlgorithm } {
  const ephemPoint = ephemeralPublicKey.length === 33 && ephemeralPublicKey[0] === 0x40
    ? ephemeralPublicKey.subarray(1)
    : ephemeralPublicKey;

  let sharedSecret: Uint8Array;
  try {
    sharedSecret = x25519.getSharedSecret(recipientPrivateKey, ephemPoint);
  } catch (err: any) {
    throw new PGPDecryptionError(`X25519 ECDH shared secret computation failed: ${err.message}`);
  }

  const kekSize = getCipherKeySize(kdfSymmetricAlgorithm);
  const paramBytes = concatBytes(
    new Uint8Array([X25519_OID.length]),
    X25519_OID,
    new Uint8Array([18]), // PublicKeyAlgorithm.ECDH
    new Uint8Array([3, 1, hashAlgorithm, kdfSymmetricAlgorithm]),
    new Uint8Array([0x41, 0x6e, 0x6f, 0x6e, 0x79, 0x6d, 0x6f, 0x75, 0x73, 0x20, 0x53, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x20, 0x20, 0x20, 0x20]),
    recipientFingerprint
  );

  const kek = kdfX963(sharedSecret, kekSize, hashAlgorithm, paramBytes);

  let paddedKey: Uint8Array;
  try {
    paddedKey = aeskw(kek).decrypt(wrappedKey);
  } catch (err: any) {
    throw new PGPDecryptionError(`AES Key Unwrap failed: ${err.message}`);
  }

  const padLen = paddedKey[paddedKey.length - 1];
  if (padLen < 1 || padLen > 8 || padLen > paddedKey.length) {
    throw new PGPDecryptionError("Invalid PKCS#5 padding in unwrapped session key");
  }

  const unpadded = paddedKey.subarray(0, paddedKey.length - padLen);
  const symmetricAlgorithm = unpadded[0] as SymmetricKeyAlgorithm;
  const sessionKey = unpadded.subarray(1);

  return { sessionKey, symmetricAlgorithm };
}
