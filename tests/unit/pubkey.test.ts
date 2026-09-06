import { describe, it, expect } from 'vitest';
import {
  generateRSAKeyPair,
  encryptRSA,
  decryptRSA,
  signRSA,
  verifyRSA
} from '../../packages/core/src/crypto/rsa.js';
import {
  generateECCKeyPair,
  signECC,
  verifyECC,
  encryptECDH,
  decryptECDH
} from '../../packages/core/src/crypto/ecc.js';
import {
  HashAlgorithm,
  SymmetricKeyAlgorithm
} from '../../packages/core/src/types/enums.js';
import { hash } from '../../packages/core/src/crypto/hash.js';
import { utf8ToBytes, bytesToUtf8 } from '../../packages/core/src/utils/bytes.js';
import { getRandomBytes } from '../../packages/core/src/utils/random.js';

describe('RSA Cryptography', () => {
  it('generates 2048-bit RSA key and performs encrypt/decrypt roundtrip', async () => {
    const keyPair = await generateRSAKeyPair(2048);
    expect(keyPair.n).toBeGreaterThan(0n);
    expect(keyPair.e).toBe(65537n);

    const sessionKey = getRandomBytes(32);
    const encrypted = encryptRSA(keyPair, sessionKey);
    const decrypted = decryptRSA(keyPair, encrypted);

    expect(decrypted).toEqual(sessionKey);
  }, 10000);

  it('signs and verifies with RSA', async () => {
    const keyPair = await generateRSAKeyPair(2048);
    const data = utf8ToBytes('OpenPGP RSA Signature Test');
    const digest = hash(HashAlgorithm.SHA256, data);

    const signature = signRSA(keyPair, HashAlgorithm.SHA256, digest);
    const isValid = verifyRSA(keyPair, HashAlgorithm.SHA256, digest, signature);
    expect(isValid).toBe(true);

    const badDigest = hash(HashAlgorithm.SHA256, utf8ToBytes('Tampered'));
    const isBadValid = verifyRSA(keyPair, HashAlgorithm.SHA256, badDigest, signature);
    expect(isBadValid).toBe(false);
  }, 10000);
});

describe('ECC Cryptography', () => {
  it('signs and verifies with Ed25519', () => {
    const keyPair = generateECCKeyPair('ed25519');
    const data = utf8ToBytes('Ed25519 message to sign');
    const digest = hash(HashAlgorithm.SHA256, data);

    const { r, s } = signECC('ed25519', keyPair.privateKey, digest);
    const isValid = verifyECC('ed25519', keyPair.publicKey, digest, r, s);
    expect(isValid).toBe(true);

    const badDigest = hash(HashAlgorithm.SHA256, utf8ToBytes('Corrupted'));
    expect(verifyECC('ed25519', keyPair.publicKey, badDigest, r, s)).toBe(false);
  });

  it('performs ECDH key agreement with Curve25519 and wraps session key', () => {
    const recipient = generateECCKeyPair('curve25519');
    const recipientFingerprint = getRandomBytes(20);
    const sessionKey = getRandomBytes(32); // AES-256 session key

    const { ephemeralPublicKey, wrappedKey } = encryptECDH(
      'curve25519',
      recipient.publicKey,
      recipientFingerprint,
      sessionKey,
      SymmetricKeyAlgorithm.AES256
    );

    const decrypted = decryptECDH(
      'curve25519',
      recipient.privateKey,
      recipientFingerprint,
      ephemeralPublicKey,
      wrappedKey
    );

    expect(decrypted.symmetricAlgorithm).toBe(SymmetricKeyAlgorithm.AES256);
    expect(decrypted.sessionKey).toEqual(sessionKey);
  });

  it('signs and verifies with NIST P-256', () => {
    const keyPair = generateECCKeyPair('p256');
    const data = utf8ToBytes('P256 message to sign');
    const digest = hash(HashAlgorithm.SHA256, data);

    const { r, s } = signECC('p256', keyPair.privateKey, digest);
    const isValid = verifyECC('p256', keyPair.publicKey, digest, r, s);
    expect(isValid).toBe(true);
  });
});
