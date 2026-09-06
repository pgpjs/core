import { PGPParseError } from '../errors/index.js';
import { readUint16BE } from './bytes.js';

export interface MPI {
  bitLength: number;
  data: Uint8Array;
  byteLength: number; // total bytes consumed including the 2-byte length prefix
}

/**
 * Parses an MPI from a buffer starting at offset.
 */
export function parseMPI(buf: Uint8Array, offset: number = 0): MPI {
  if (buf.length < offset + 2) {
    throw new PGPParseError('Buffer too small to contain MPI bit length');
  }
  const bitLength = readUint16BE(buf, offset);
  const dataByteLength = Math.floor((bitLength + 7) / 8);

  if (buf.length < offset + 2 + dataByteLength) {
    throw new PGPParseError(
      `Buffer too small for MPI data: expected ${dataByteLength} bytes, found ${buf.length - offset - 2}`
    );
  }

  const data = buf.subarray(offset + 2, offset + 2 + dataByteLength);
  return {
    bitLength,
    data,
    byteLength: 2 + dataByteLength
  };
}

/**
 * Calculates the bit length of a big-endian byte array.
 */
export function calculateBitLength(bytes: Uint8Array): number {
  let start = 0;
  while (start < bytes.length && bytes[start] === 0) {
    start++;
  }
  if (start === bytes.length) {
    return 0;
  }
  const firstByte = bytes[start];
  const msbBits = 32 - Math.clz32(firstByte);
  const remainingBytes = bytes.length - start - 1;
  return msbBits + remainingBytes * 8;
}

/**
 * Serializes raw bytes or a BigInt into an OpenPGP MPI format.
 */
export function serializeMPI(input: Uint8Array | bigint): Uint8Array {
  let bytes: Uint8Array;
  if (typeof input === 'bigint') {
    if (input === 0n) {
      return new Uint8Array([0, 0]);
    }
    let hex = input.toString(16);
    if (hex.length % 2 !== 0) {
      hex = '0' + hex;
    }
    const len = hex.length / 2;
    bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }
  } else {
    // Strip leading zeros
    let start = 0;
    while (start < input.length && input[start] === 0) {
      start++;
    }
    if (start === input.length) {
      return new Uint8Array([0, 0]);
    }
    bytes = input.subarray(start);
  }

  const bitLength = calculateBitLength(bytes);
  const result = new Uint8Array(2 + bytes.length);
  result[0] = (bitLength >> 8) & 0xff;
  result[1] = bitLength & 0xff;
  result.set(bytes, 2);
  return result;
}

/**
 * Converts MPI bytes back to BigInt.
 */
export function mpiToBigInt(data: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < data.length; i++) {
    result = (result << 8n) | BigInt(data[i]);
  }
  return result;
}
