import { HashAlgorithm } from '../../../types/enums.js';
import { PGPDecryptionError, PGPEncryptionError, PGPSignatureError, PGPVerificationError } from '../../../errors/index.js';
import { bytesEqual, concatBytes } from '../../../utils/bytes.js';
import { getRandomBytes } from '../../../utils/random.js';
import { HASH_DIGEST_INFO_PREFIXES } from '../../hash/index.js';

export interface RSAPublicKey {
  n: bigint;
  e: bigint;
}

export interface RSAPrivateKey extends RSAPublicKey {
  d: bigint;
  p?: bigint;
  q?: bigint;
  u?: bigint; // q^-1 mod p (CRT coefficient)
}

/**
 * Modular exponentiation: (base ^ exp) mod mod
 */
export function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = ((base % mod) + mod) % mod;
  let e = exp;

  while (e > 0n) {
    if (e & 1n) {
      result = (result * base) % mod;
    }
    base = (base * base) % mod;
    e >>= 1n;
  }
  return result;
}

/**
 * Extended Euclidean algorithm to compute modular inverse.
 */
export function modInverse(a: bigint, m: bigint): bigint {
  let [m0, x0, x1] = [m, 0n, 1n];
  if (m === 1n) return 0n;

  let [a0, b0] = [a % m, m];
  while (a0 > 1n) {
    const q = a0 / b0;
    let t = b0;
    b0 = a0 % b0;
    a0 = t;
    t = x0;
    x0 = x1 - q * x0;
    x1 = t;
  }
  if (x1 < 0n) x1 += m0;
  return x1;
}

/**
 * Converts BigInt to big-endian byte array of specified length.
 */
export function bigIntToBytes(val: bigint, length?: number): Uint8Array {
  let hex = val.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const rawBytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < rawBytes.length; i++) {
    rawBytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  if (length === undefined || rawBytes.length === length) {
    return rawBytes;
  }
  if (rawBytes.length > length) {
    // Strip leading zero bytes if possible
    let start = 0;
    while (start < rawBytes.length && rawBytes[start] === 0 && rawBytes.length - start > length) {
      start++;
    }
    return rawBytes.subarray(start);
  }
  const padded = new Uint8Array(length);
  padded.set(rawBytes, length - rawBytes.length);
  return padded;
}

/**
 * Converts big-endian byte array to BigInt.
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function base64UrlToBigInt(b64url: string): bigint {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytesToBigInt(bytes);
}

/**
 * Generates an RSA Key Pair using WebCrypto with full JWK CRT export.
 */
export async function generateRSAKeyPair(bits: 2048 | 3072 | 4096 = 2048): Promise<RSAPrivateKey> {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj?.subtle) {
    throw new Error('WebCrypto subtle is required for RSA key generation');
  }

  const keyPair = await cryptoObj.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]), // 65537
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );

  const jwk = await cryptoObj.subtle.exportKey('jwk', keyPair.privateKey);

  if (!jwk.n || !jwk.e || !jwk.d || !jwk.p || !jwk.q || !jwk.qi) {
    throw new Error('Failed to export full RSA JWK parameters');
  }

  return {
    n: base64UrlToBigInt(jwk.n),
    e: base64UrlToBigInt(jwk.e),
    d: base64UrlToBigInt(jwk.d),
    p: base64UrlToBigInt(jwk.p),
    q: base64UrlToBigInt(jwk.q),
    u: base64UrlToBigInt(jwk.qi)
  };
}

/**
 * Encrypts a session key using RSAES-PKCS1-v1_5 (RFC 4880 / RFC 3447).
 */
export function encryptRSA(publicKey: RSAPublicKey, plaintext: Uint8Array): Uint8Array {
  const k = Math.floor((publicKey.n.toString(16).length + 1) / 2); // modulus length in bytes
  const mLen = plaintext.length;

  if (mLen > k - 11) {
    throw new PGPEncryptionError(`Message too long for RSA key size: max ${k - 11} bytes`);
  }

  // PKCS#1 v1.5 padding for encryption:
  // EM = 0x00 || 0x02 || PS || 0x00 || M
  // PS has at least 8 non-zero random octets
  const psLen = k - mLen - 3;
  const ps = new Uint8Array(psLen);

  for (let i = 0; i < psLen; i++) {
    let b = 0;
    while (b === 0) {
      b = getRandomBytes(1)[0];
    }
    ps[i] = b;
  }

  const em = new Uint8Array(k);
  em[0] = 0x00;
  em[1] = 0x02;
  em.set(ps, 2);
  em[2 + psLen] = 0x00;
  em.set(plaintext, 2 + psLen + 1);

  const m = bytesToBigInt(em);
  const c = modPow(m, publicKey.e, publicKey.n);
  return bigIntToBytes(c, k);
}

/**
 * Decrypts a session key using RSAES-PKCS1-v1_5 with side-channel blinding.
 */
export function decryptRSA(privateKey: RSAPrivateKey, ciphertext: Uint8Array): Uint8Array {
  const k = Math.floor((privateKey.n.toString(16).length + 1) / 2);
  const c = bytesToBigInt(ciphertext);

  if (c >= privateKey.n) {
    throw new PGPDecryptionError('Ciphertext representative out of range');
  }

  // Blinding: choose random r in [2, n-2]
  const rBytes = getRandomBytes(Math.min(32, k - 1));
  const r = (bytesToBigInt(rBytes) % (privateKey.n - 3n)) + 2n;
  const rInv = modInverse(r, privateKey.n);
  const re = modPow(r, privateKey.e, privateKey.n);

  // Blinded c' = (c * r^e) mod n
  const cBlinded = (c * re) % privateKey.n;

  // Decrypt
  let mBlinded: bigint;
  if (privateKey.p && privateKey.q && privateKey.u) {
    // CRT acceleration
    const p = privateKey.p;
    const q = privateKey.q;
    const dp = privateKey.d % (p - 1n);
    const dq = privateKey.d % (q - 1n);
    const m1 = modPow(cBlinded % p, dp, p);
    const m2 = modPow(cBlinded % q, dq, q);
    let h = ((privateKey.u * (m1 - m2)) % p + p) % p;
    mBlinded = m2 + h * q;
  } else {
    mBlinded = modPow(cBlinded, privateKey.d, privateKey.n);
  }

  // Unblind: m = (m' * r^-1) mod n
  const m = (mBlinded * rInv) % privateKey.n;
  const em = bigIntToBytes(m, k);

  // PKCS#1 v1.5 unpadding: 0x00 0x02 PS 0x00 M
  if (em[0] !== 0x00 || em[1] !== 0x02) {
    throw new PGPDecryptionError('Invalid PKCS#1 v1.5 encryption padding');
  }

  let sepIndex = -1;
  for (let i = 2; i < em.length; i++) {
    if (em[i] === 0x00) {
      sepIndex = i;
      break;
    }
  }

  if (sepIndex === -1 || sepIndex < 10) {
    throw new PGPDecryptionError('Malformed PKCS#1 v1.5 padding separator');
  }

  return em.subarray(sepIndex + 1);
}

/**
 * Signs hash digest using RSASSA-PKCS1-v1_5.
 */
export function signRSA(
  privateKey: RSAPrivateKey,
  hashAlgorithm: HashAlgorithm,
  digest: Uint8Array
): Uint8Array {
  const k = Math.floor((privateKey.n.toString(16).length + 1) / 2);
  const prefix = HASH_DIGEST_INFO_PREFIXES[hashAlgorithm];
  if (!prefix) {
    throw new PGPSignatureError(`Unsupported RSA signature hash algorithm: ${hashAlgorithm}`);
  }

  const digestInfo = concatBytes(prefix, digest);
  const tLen = digestInfo.length;

  if (k < tLen + 11) {
    throw new PGPSignatureError('RSA key size too short for signature digest');
  }

  // EM = 0x00 || 0x01 || PS (0xFF) || 0x00 || T
  const psLen = k - tLen - 3;
  const em = new Uint8Array(k);
  em[0] = 0x00;
  em[1] = 0x01;
  em.fill(0xff, 2, 2 + psLen);
  em[2 + psLen] = 0x00;
  em.set(digestInfo, 2 + psLen + 1);

  const m = bytesToBigInt(em);
  let s: bigint;

  if (privateKey.p && privateKey.q && privateKey.u) {
    const p = privateKey.p;
    const q = privateKey.q;
    const dp = privateKey.d % (p - 1n);
    const dq = privateKey.d % (q - 1n);
    const m1 = modPow(m % p, dp, p);
    const m2 = modPow(m % q, dq, q);
    let h = ((privateKey.u * (m1 - m2)) % p + p) % p;
    s = m2 + h * q;
  } else {
    s = modPow(m, privateKey.d, privateKey.n);
  }

  return bigIntToBytes(s, k);
}

/**
 * Verifies RSASSA-PKCS1-v1_5 signature.
 */
export function verifyRSA(
  publicKey: RSAPublicKey,
  hashAlgorithm: HashAlgorithm,
  digest: Uint8Array,
  signature: Uint8Array
): boolean {
  const k = Math.floor((publicKey.n.toString(16).length + 1) / 2);
  const s = bytesToBigInt(signature);

  if (s >= publicKey.n) {
    return false;
  }

  const m = modPow(s, publicKey.e, publicKey.n);
  const em = bigIntToBytes(m, k);

  const prefix = HASH_DIGEST_INFO_PREFIXES[hashAlgorithm];
  if (!prefix) {
    return false;
  }
  const digestInfo = concatBytes(prefix, digest);
  const tLen = digestInfo.length;

  if (k < tLen + 11) {
    return false;
  }

  if (em[0] !== 0x00 || em[1] !== 0x01) {
    return false;
  }

  const psLen = k - tLen - 3;
  for (let i = 2; i < 2 + psLen; i++) {
    if (em[i] !== 0xff) {
      return false;
    }
  }

  if (em[2 + psLen] !== 0x00) {
    return false;
  }

  const extracted = em.subarray(2 + psLen + 1);
  return bytesEqual(extracted, digestInfo);
}
