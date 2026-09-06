import { PacketTag } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { concatBytes, readUint16BE, readUint32BE } from '../utils/bytes.js';

export interface PacketHeader {
  tag: PacketTag;
  bodyOffset: number;
  bodyLength: number;
  totalLength: number;
  isNewFormat: boolean;
}

/**
 * Parses an OpenPGP packet header from buffer at given offset.
 */
export function parsePacketHeader(buf: Uint8Array, offset: number = 0): PacketHeader {
  if (buf.length < offset + 1) {
    throw new PGPParseError('Buffer too small for packet header');
  }

  const firstByte = buf[offset];
  if ((firstByte & 0x80) === 0) {
    throw new PGPParseError(`Invalid packet header: bit 7 must be 1 (got 0x${firstByte.toString(16)})`);
  }

  const isNewFormat = (firstByte & 0x40) !== 0;

  if (isNewFormat) {
    const tag = (firstByte & 0x3f) as PacketTag;
    if (buf.length < offset + 2) {
      throw new PGPParseError('Buffer too small for new format length');
    }

    const lenByte1 = buf[offset + 1];

    if (lenByte1 < 192) {
      // 1-octet length
      const bodyLength = lenByte1;
      return {
        tag,
        bodyOffset: offset + 2,
        bodyLength,
        totalLength: 2 + bodyLength,
        isNewFormat: true
      };
    } else if (lenByte1 < 224) {
      // 2-octet length
      if (buf.length < offset + 3) {
        throw new PGPParseError('Buffer too small for 2-octet length');
      }
      const lenByte2 = buf[offset + 2];
      const bodyLength = ((lenByte1 - 192) << 8) + lenByte2 + 192;
      return {
        tag,
        bodyOffset: offset + 3,
        bodyLength,
        totalLength: 3 + bodyLength,
        isNewFormat: true
      };
    } else if (lenByte1 === 255) {
      // 5-octet length
      if (buf.length < offset + 6) {
        throw new PGPParseError('Buffer too small for 5-octet length');
      }
      const bodyLength = readUint32BE(buf, offset + 2);
      return {
        tag,
        bodyOffset: offset + 6,
        bodyLength,
        totalLength: 6 + bodyLength,
        isNewFormat: true
      };
    } else {
      // Partial body length
      const partialLen = 1 << (lenByte1 & 0x1f);
      // For now calculate until remaining or read chunks
      const bodyLength = Math.min(partialLen, buf.length - offset - 2);
      return {
        tag,
        bodyOffset: offset + 2,
        bodyLength,
        totalLength: 2 + bodyLength,
        isNewFormat: true
      };
    }
  } else {
    // Old format
    const tag = ((firstByte >> 2) & 0x0f) as PacketTag;
    const lenType = firstByte & 0x03;

    switch (lenType) {
      case 0: {
        if (buf.length < offset + 2) {
          throw new PGPParseError('Buffer too small for 1-octet old length');
        }
        const bodyLength = buf[offset + 1];
        return {
          tag,
          bodyOffset: offset + 2,
          bodyLength,
          totalLength: 2 + bodyLength,
          isNewFormat: false
        };
      }

      case 1: {
        if (buf.length < offset + 3) {
          throw new PGPParseError('Buffer too small for 2-octet old length');
        }
        const bodyLength = readUint16BE(buf, offset + 1);
        return {
          tag,
          bodyOffset: offset + 3,
          bodyLength,
          totalLength: 3 + bodyLength,
          isNewFormat: false
        };
      }

      case 2: {
        if (buf.length < offset + 5) {
          throw new PGPParseError('Buffer too small for 4-octet old length');
        }
        const bodyLength = readUint32BE(buf, offset + 1);
        return {
          tag,
          bodyOffset: offset + 5,
          bodyLength,
          totalLength: 5 + bodyLength,
          isNewFormat: false
        };
      }

      case 3: {
        // Indeterminate length: extends to end of buffer
        const bodyLength = buf.length - offset - 1;
        return {
          tag,
          bodyOffset: offset + 1,
          bodyLength,
          totalLength: 1 + bodyLength,
          isNewFormat: false
        };
      }

      default:
        throw new PGPParseError(`Invalid length type: ${lenType}`);
    }
  }
}

/**
 * Serializes a new-format OpenPGP packet header for given tag and body length.
 */
export function serializePacketHeader(tag: PacketTag, bodyLength: number): Uint8Array {
  const firstByte = 0xc0 | (tag & 0x3f);

  if (bodyLength < 192) {
    return new Uint8Array([firstByte, bodyLength]);
  } else if (bodyLength < 8384) {
    const adjusted = bodyLength - 192;
    const octet1 = ((adjusted >> 8) & 0xff) + 192;
    const octet2 = adjusted & 0xff;
    return new Uint8Array([firstByte, octet1, octet2]);
  } else {
    return new Uint8Array([
      firstByte,
      0xff,
      (bodyLength >>> 24) & 0xff,
      (bodyLength >>> 16) & 0xff,
      (bodyLength >>> 8) & 0xff,
      bodyLength & 0xff
    ]);
  }
}

/**
 * Packages packet body with new-format packet header.
 */
export function wrapPacket(tag: PacketTag, body: Uint8Array): Uint8Array {
  const header = serializePacketHeader(tag, body.length);
  return concatBytes(header, body);
}
