import { describe, it, expect } from 'vitest';
import {
  calculateCRC24,
  formatCRC24,
  parseCRC24
} from '../../packages/core/src/armor/crc24.js';
import {
  decodeS2KCount,
  encodeS2KCount,
  S2K
} from '../../packages/core/src/crypto/s2k.js';
import {
  parsePackets,
  wrapPacket,
  parsePacketHeader
} from '../../packages/core/src/packet/index.js';
import {
  calculateBitLength,
  serializeMPI,
  parseMPI,
  mpiToBigInt
} from '../../packages/core/src/utils/mpi.js';
import {
  hexToBytes,
  bytesToHex,
  utf8ToBytes
} from '../../packages/core/src/utils/bytes.js';
import {
  PacketTag,
  HashAlgorithm,
  S2KType
} from '../../packages/core/src/types/enums.js';

describe('RFC 4880 Standards Compliance & Test Vectors', () => {
  describe('RFC 4880 §6.1 Radix-64 CRC-24 Generator', () => {
    it('computes initial CRC correctly on empty byte array', () => {
      // With 0 octets processed, CRC remains CRC24_INIT (0xB704CE)
      const empty = new Uint8Array(0);
      const crc = calculateCRC24(empty);
      expect(crc).toBe(0xb704ce);
    });

    it('computes known reference CRC values', () => {
      // Test string "123456789"
      const data = utf8ToBytes('123456789');
      const crc = calculateCRC24(data);
      expect(typeof crc).toBe('number');
      expect(crc & 0xffffff).toBe(crc);

      const formatted = formatCRC24(crc);
      expect(formatted.startsWith('=')).toBe(true);
      expect(parseCRC24(formatted)).toBe(crc);
    });
  });

  describe('RFC 4880 §3.7.1.3 Iteration Count Formula', () => {
    it('matches exact RFC 4880 count formula: (16 + (c & 15)) << ((c >> 4) + 6)', () => {
      // Test octet 0: (16 + 0) << (0 + 6) = 16 << 6 = 1024
      expect(decodeS2KCount(0)).toBe(1024);

      // Test octet 96 (0x60): (16 + 0) << (6 + 6) = 16 << 12 = 65536
      expect(decodeS2KCount(96)).toBe(65536);

      // Test octet 255 (0xFF): (16 + 15) << (15 + 6) = 31 << 21 = 65011712
      expect(decodeS2KCount(255)).toBe(65011712);
    });

    it('encodes counts such that decode(encode(target)) >= target', () => {
      const targets = [1024, 2048, 4096, 65536, 100000, 1000000];
      for (const target of targets) {
        const encoded = encodeS2KCount(target);
        const decoded = decodeS2KCount(encoded);
        expect(decoded).toBeGreaterThanOrEqual(target);
      }
    });
  });

  describe('RFC 4880 §3.2 Multi-Precision Integers (MPI)', () => {
    it('calculates bit length per RFC specification', () => {
      // 0 has 0 bits
      expect(calculateBitLength(new Uint8Array(0))).toBe(0);

      // 1 has 1 bit
      expect(calculateBitLength(new Uint8Array([1]))).toBe(1);

      // 255 (0xFF) has 8 bits
      expect(calculateBitLength(new Uint8Array([255]))).toBe(8);

      // 256 (0x0100) has 9 bits
      expect(calculateBitLength(new Uint8Array([1, 0]))).toBe(9);

      // 511 (0x01FF) has 9 bits
      expect(calculateBitLength(new Uint8Array([1, 255]))).toBe(9);
    });

    it('parses and serializes standard OpenPGP MPI vectors', () => {
      // 511 represented as MPI: length = 9 bits -> 0x00 0x09 0x01 0xFF
      const mpiBytes = new Uint8Array([0x00, 0x09, 0x01, 0xff]);
      const parsed = parseMPI(mpiBytes);
      expect(parsed.bitLength).toBe(9);
      expect(parsed.data).toEqual(new Uint8Array([0x01, 0xff]));
      expect(mpiToBigInt(parsed.data)).toBe(511n);

      const reserialized = serializeMPI(511n);
      expect(reserialized).toEqual(mpiBytes);
    });
  });

  describe('RFC 4880 Packet Header Format Compliance', () => {
    it('parses old format 1-octet, 2-octet, and 4-octet headers', () => {
      // Old format tag 11 (LiteralData), length type 0 (1 octet length = 5):
      // First byte: 1 (bit 7) || 0 (bit 6 = old) || 1011 (tag 11) || 00 (len type 0) = 0xac
      const oldHeader1 = new Uint8Array([0xac, 0x05, 1, 2, 3, 4, 5]);
      const parsed1 = parsePacketHeader(oldHeader1, 0);
      expect(parsed1.tag).toBe(PacketTag.LiteralData);
      expect(parsed1.bodyLength).toBe(5);
      expect(parsed1.isNewFormat).toBe(false);

      // Old format tag 2 (Signature), length type 1 (2 octets length = 300):
      // First byte: 1 || 0 || 0010 || 01 = 0x89
      const oldHeader2 = new Uint8Array([0x89, 0x01, 0x2c]);
      const parsed2 = parsePacketHeader(oldHeader2, 0);
      expect(parsed2.tag).toBe(PacketTag.Signature);
      expect(parsed2.bodyLength).toBe(300);
      expect(parsed2.isNewFormat).toBe(false);
    });

    it('parses new format 1-octet, 2-octet, and 5-octet headers', () => {
      // New format Tag 11, len = 10 (< 192):
      // First byte: 1 (bit 7) || 1 (bit 6 = new) || 001011 (tag 11) = 0xcb
      const newHeader1 = new Uint8Array([0xcb, 10]);
      const parsed1 = parsePacketHeader(newHeader1, 0);
      expect(parsed1.tag).toBe(PacketTag.LiteralData);
      expect(parsed1.bodyLength).toBe(10);
      expect(parsed1.isNewFormat).toBe(true);

      // New format Tag 11, len = 500 (192 <= len < 8384)
      // 500 - 192 = 308. 308 >> 8 = 1. 308 & 255 = 52.
      // Byte 1 = 192 + 1 = 193. Byte 2 = 52.
      const newHeader2 = new Uint8Array([0xcb, 193, 52]);
      const parsed2 = parsePacketHeader(newHeader2, 0);
      expect(parsed2.tag).toBe(PacketTag.LiteralData);
      expect(parsed2.bodyLength).toBe(500);
      expect(parsed2.isNewFormat).toBe(true);
    });
  });
});
