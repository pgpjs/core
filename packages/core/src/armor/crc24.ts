import { bytesToBase64 } from '../utils/bytes.js';

export const CRC24_INIT = 0xb704ce;
export const CRC24_POLY = 0x1864cfb;

/**
 * Precomputed lookup table for 8-bit CRC-24 calculation.
 */
const CRC24_TABLE = new Int32Array(256);
for (let i = 0; i < 256; i++) {
  let crc = i << 16;
  for (let j = 0; j < 8; j++) {
    crc <<= 1;
    if (crc & 0x1000000) {
      crc ^= CRC24_POLY;
    }
  }
  CRC24_TABLE[i] = crc & 0xffffff;
}

/**
 * Calculates RFC 4880 Radix-64 CRC-24 checksum.
 */
export function calculateCRC24(data: Uint8Array): number {
  let crc = CRC24_INIT;
  for (let i = 0; i < data.length; i++) {
    const tableIndex = ((crc >> 16) ^ data[i]) & 0xff;
    crc = ((crc << 8) ^ CRC24_TABLE[tableIndex]) & 0xffffff;
  }
  return crc;
}

/**
 * Encodes a 24-bit integer into an RFC 4880 armor checksum string (e.g. "=abcd").
 */
export function formatCRC24(crc: number): string {
  const bytes = new Uint8Array([
    (crc >> 16) & 0xff,
    (crc >> 8) & 0xff,
    crc & 0xff
  ]);
  return '=' + bytesToBase64(bytes);
}

/**
 * Parses a 4-character base64 checksum string (without '=') into a 24-bit number.
 */
export function parseCRC24(checksumBase64: string): number {
  const clean = checksumBase64.startsWith('=') ? checksumBase64.slice(1) : checksumBase64;
  if (clean.length !== 4) {
    throw new Error(`Invalid CRC-24 checksum length: expected 4 base64 chars, got ${clean.length}`);
  }
  const binary = atob(clean);
  if (binary.length !== 3) {
    throw new Error('Invalid CRC-24 checksum decoding');
  }
  return (
    (binary.charCodeAt(0) << 16) |
    (binary.charCodeAt(1) << 8) |
    binary.charCodeAt(2)
  );
}
