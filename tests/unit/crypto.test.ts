import { describe, it, expect } from 'vitest';
import { calculateCRC24, formatCRC24, parseCRC24 } from '../../packages/core/src/armor/crc24.js';
import {
  getHash,
  hash,
  getHashDigestLength,
  getHashName,
  getHashAlgorithmByName,
  HASH_DIGEST_INFO_PREFIXES
} from '../../packages/core/src/crypto/hash.js';
import { S2K, parseS2K, decodeS2KCount, encodeS2KCount } from '../../packages/core/src/crypto/s2k.js';
import {
  encryptCFB,
  decryptCFB,
  encryptRawCFB,
  decryptRawCFB
} from '../../packages/core/src/crypto/cfb.js';
import {
  HashAlgorithm,
  SymmetricKeyAlgorithm,
  S2KType
} from '../../packages/core/src/types/enums.js';
import {
  utf8ToBytes,
  bytesToUtf8,
  bytesToHex,
  hexToBytes
} from '../../packages/core/src/utils/bytes.js';
import { PGPDecryptionError } from '../../packages/core/src/errors/index.js';

describe('CRC-24 checksum', () => {
  it('calculates CRC-24 consistently', () => {
    const data = utf8ToBytes('OpenPGP CRC24 test');
    const crc = calculateCRC24(data);
    expect(typeof crc).toBe('number');
    expect(crc).toBeGreaterThan(0);
    const formatted = formatCRC24(crc);
    expect(formatted.startsWith('=')).toBe(true);
    expect(parseCRC24(formatted)).toBe(crc);
  });
});

describe('Hash subsystem', () => {
  it('hashes with SHA-256', () => {
    const data = utf8ToBytes('abc');
    const digest = hash(HashAlgorithm.SHA256, data);
    expect(bytesToHex(digest)).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  });

  it('provides correct digest lengths', () => {
    expect(getHashDigestLength(HashAlgorithm.SHA256)).toBe(32);
    expect(getHashDigestLength(HashAlgorithm.SHA512)).toBe(64);
    expect(getHashDigestLength(HashAlgorithm.SHA1)).toBe(20);
    expect(getHashDigestLength(HashAlgorithm.RIPEMD160)).toBe(20);
  });

  it('maps names and ASN.1 prefixes', () => {
    expect(getHashAlgorithmByName('sha256')).toBe(HashAlgorithm.SHA256);
    expect(getHashName(HashAlgorithm.SHA256)).toBe('SHA256');
    expect(HASH_DIGEST_INFO_PREFIXES[HashAlgorithm.SHA256].length).toBe(19);
  });
});

describe('String-to-Key (S2K)', () => {
  it('encodes and decodes iteration counts', () => {
    const count = 65536;
    const encoded = encodeS2KCount(count);
    const decoded = decodeS2KCount(encoded);
    expect(decoded).toBeGreaterThanOrEqual(count);
  });

  it('derives keys with Simple S2K', () => {
    const s2k = new S2K({ type: S2KType.Simple, hashAlgorithm: HashAlgorithm.SHA256 });
    const key16 = s2k.deriveKey('password', 16);
    const key32 = s2k.deriveKey('password', 32);
    expect(key16.length).toBe(16);
    expect(key32.length).toBe(32);
    expect(key32.subarray(0, 16)).toEqual(key16);
  });

  it('derives keys and serializes Salted S2K', () => {
    const s2k = new S2K({ type: S2KType.Salted, hashAlgorithm: HashAlgorithm.SHA256 });
    const serialized = s2k.serialize();
    expect(serialized.length).toBe(10);
    const { s2k: parsed } = parseS2K(serialized);
    expect(parsed.type).toBe(S2KType.Salted);
    const key1 = s2k.deriveKey('password', 32);
    const key2 = parsed.deriveKey('password', 32);
    expect(key1).toEqual(key2);
  });

  it('derives keys and serializes Iterated and Salted S2K', () => {
    const s2k = new S2K({
      type: S2KType.IteratedAndSalted,
      hashAlgorithm: HashAlgorithm.SHA256,
      count: 65536
    });
    const serialized = s2k.serialize();
    expect(serialized.length).toBe(11);
    const { s2k: parsed } = parseS2K(serialized);
    expect(parsed.type).toBe(S2KType.IteratedAndSalted);
    const key1 = s2k.deriveKey('my-secret-passphrase', 32);
    const key2 = parsed.deriveKey('my-secret-passphrase', 32);
    expect(key1).toEqual(key2);
  });
});

describe('OpenPGP CFB Mode', () => {
  it('encrypts and decrypts with AES-128, AES-192, and AES-256', () => {
    const algorithms = [
      SymmetricKeyAlgorithm.AES128,
      SymmetricKeyAlgorithm.AES192,
      SymmetricKeyAlgorithm.AES256
    ];

    for (const algo of algorithms) {
      const keyLength = algo === SymmetricKeyAlgorithm.AES128 ? 16 : algo === SymmetricKeyAlgorithm.AES192 ? 24 : 32;
      const key = new Uint8Array(keyLength).fill(0x42);
      const plaintext = utf8ToBytes('Hello, OpenPGP CFB Mode Encryption & Decryption!');

      const ciphertext = encryptCFB(algo, key, plaintext);
      const decrypted = decryptCFB(algo, key, ciphertext);
      expect(bytesToUtf8(decrypted)).toBe('Hello, OpenPGP CFB Mode Encryption & Decryption!');
    }
  });

  it('throws on wrong key or tampered ciphertext', () => {
    const key = new Uint8Array(32).fill(0x01);
    const wrongKey = new Uint8Array(32).fill(0x02);
    const plaintext = utf8ToBytes('Secret message');

    const ciphertext = encryptCFB(SymmetricKeyAlgorithm.AES256, key, plaintext);

    // Wrong key
    expect(() => decryptCFB(SymmetricKeyAlgorithm.AES256, wrongKey, ciphertext)).toThrow(
      PGPDecryptionError
    );

    // Tampered ciphertext
    const tampered = new Uint8Array(ciphertext);
    tampered[10] ^= 0xff;
    expect(() => decryptCFB(SymmetricKeyAlgorithm.AES256, key, tampered)).toThrow(
      PGPDecryptionError
    );
  });

  it('performs raw CFB encryption and decryption', () => {
    const key = new Uint8Array(16).fill(0x55);
    const iv = new Uint8Array(16).fill(0xaa);
    const plaintext = utf8ToBytes('Raw CFB without prefix');

    const ciphertext = encryptRawCFB(SymmetricKeyAlgorithm.AES128, key, iv, plaintext);
    const decrypted = decryptRawCFB(SymmetricKeyAlgorithm.AES128, key, iv, ciphertext);
    expect(bytesToUtf8(decrypted)).toBe('Raw CFB without prefix');
  });
});
