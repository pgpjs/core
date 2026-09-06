import { describe, it, expect } from 'vitest';
import {
  concatBytes,
  bytesEqual,
  bytesToHex,
  hexToBytes,
  utf8ToBytes,
  bytesToUtf8,
  bytesToBase64,
  base64ToBytes,
  getRandomBytes,
  parseMPI,
  serializeMPI,
  mpiToBigInt,
  calculateBitLength
} from '../../packages/core/src/utils/index.js';

describe('Byte utilities', () => {
  it('concatenates bytes correctly', () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4, 5]);
    const result = concatBytes(a, b);
    expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
  });

  it('compares bytes in constant time', () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3]);
    const c = new Uint8Array([1, 2, 4]);
    expect(bytesEqual(a, b)).toBe(true);
    expect(bytesEqual(a, c)).toBe(false);
  });

  it('encodes and decodes hex', () => {
    const bytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const hex = bytesToHex(bytes);
    expect(hex).toBe('deadbeef');
    expect(hexToBytes(hex)).toEqual(bytes);
  });

  it('encodes and decodes base64', () => {
    const text = 'Hello, OpenPGP!';
    const bytes = utf8ToBytes(text);
    const b64 = bytesToBase64(bytes);
    expect(bytesToUtf8(base64ToBytes(b64))).toBe(text);
  });
});

describe('Random bytes generator', () => {
  it('generates random bytes of requested length', () => {
    const bytes = getRandomBytes(32);
    expect(bytes.length).toBe(32);
    const bytes2 = getRandomBytes(32);
    expect(bytesEqual(bytes, bytes2)).toBe(false);
  });
});

describe('MPI utilities', () => {
  it('calculates bit lengths correctly', () => {
    expect(calculateBitLength(new Uint8Array([0x01]))).toBe(1);
    expect(calculateBitLength(new Uint8Array([0x80]))).toBe(8);
    expect(calculateBitLength(new Uint8Array([0x01, 0x00]))).toBe(9);
    expect(calculateBitLength(new Uint8Array([0x00, 0x01]))).toBe(1);
  });

  it('serializes and parses MPIs accurately', () => {
    const val = 65537n; // 0x010001 (17 bits)
    const mpiBytes = serializeMPI(val);
    expect(mpiBytes[0]).toBe(0);
    expect(mpiBytes[1]).toBe(17); // 17 bits
    const parsed = parseMPI(mpiBytes);
    expect(parsed.bitLength).toBe(17);
    expect(mpiToBigInt(parsed.data)).toBe(65537n);
  });

  it('handles zero MPI', () => {
    const mpiBytes = serializeMPI(0n);
    expect(mpiBytes).toEqual(new Uint8Array([0, 0]));
    const parsed = parseMPI(mpiBytes);
    expect(parsed.bitLength).toBe(0);
    expect(parsed.data.length).toBe(0);
  });
});
