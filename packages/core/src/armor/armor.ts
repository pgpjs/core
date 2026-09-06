import { ArmorType } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { base64ToBytes, bytesToBase64 } from '../utils/bytes.js';
import { calculateCRC24, formatCRC24, parseCRC24 } from './crc24.js';

export interface Dearmored {
  type: ArmorType;
  data: Uint8Array;
  headers: Record<string, string>;
}

const LINE_LENGTH = 64;

/**
 * Encodes binary OpenPGP data into an ASCII armored string.
 */
export function armor(
  type: ArmorType,
  data: Uint8Array,
  headers: Record<string, string> = { Version: 'PGPJS v0.1.0' }
): string {
  let result = `-----BEGIN PGP ${type}-----\r\n`;

  for (const [key, value] of Object.entries(headers)) {
    result += `${key}: ${value}\r\n`;
  }
  result += '\r\n';

  const base64 = bytesToBase64(data);
  for (let i = 0; i < base64.length; i += LINE_LENGTH) {
    result += base64.slice(i, i + LINE_LENGTH) + '\r\n';
  }

  const crc = calculateCRC24(data);
  result += `${formatCRC24(crc)}\r\n`;
  result += `-----END PGP ${type}-----\r\n`;

  return result;
}

/**
 * Parses and decodes an ASCII armored OpenPGP block.
 */
export function dearmor(armoredText: string): Dearmored {
  const lines = armoredText.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');

  let startIndex = -1;
  let endIndex = -1;
  let armorType: ArmorType | undefined;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('-----BEGIN PGP ') && line.endsWith('-----')) {
      const typeStr = line.slice('-----BEGIN PGP '.length, line.length - 5);
      armorType = typeStr as ArmorType;
      startIndex = i;
      break;
    }
  }

  if (startIndex === -1 || !armorType) {
    throw new PGPParseError('No OpenPGP armor header found');
  }

  const endHeader = `-----END PGP ${armorType}-----`;
  for (let i = startIndex + 1; i < lines.length; i++) {
    if (lines[i].trim() === endHeader) {
      endIndex = i;
      break;
    }
  }

  if (endIndex === -1) {
    throw new PGPParseError(`Unclosed armor block: missing ${endHeader}`);
  }

  const headers: Record<string, string> = {};
  let bodyStartIndex = -1;

  for (let i = startIndex + 1; i < endIndex; i++) {
    const line = lines[i];
    if (line.trim() === '') {
      bodyStartIndex = i + 1;
      break;
    }
    const colonIndex = line.indexOf(':');
    if (colonIndex !== -1) {
      const key = line.slice(0, colonIndex).trim();
      const value = line.slice(colonIndex + 1).trim();
      headers[key] = value;
    }
  }

  if (bodyStartIndex === -1) {
    bodyStartIndex = startIndex + 1;
  }

  let base64Body = '';
  let expectedCRC: number | undefined;

  for (let i = bodyStartIndex; i < endIndex; i++) {
    const line = lines[i].trim();
    if (!line) continue;
    if (line.startsWith('=')) {
      expectedCRC = parseCRC24(line);
      break;
    }
    base64Body += line;
  }

  const data = base64ToBytes(base64Body);

  if (expectedCRC !== undefined) {
    const actualCRC = calculateCRC24(data);
    if (actualCRC !== expectedCRC) {
      throw new PGPParseError(
        `CRC-24 checksum mismatch: expected ${expectedCRC.toString(16)}, calculated ${actualCRC.toString(16)}`
      );
    }
  }

  return {
    type: armorType,
    data,
    headers
  };
}

/**
 * Checks if input is ASCII armored OpenPGP data.
 */
export function isArmored(input: string | Uint8Array): boolean {
  let str: string;
  if (input instanceof Uint8Array) {
    if (
      input.length >= 5 &&
      input[0] === 0x2d &&
      input[1] === 0x2d &&
      input[2] === 0x2d &&
      input[3] === 0x2d &&
      input[4] === 0x2d
    ) {
      str = new TextDecoder().decode(input);
    } else {
      return false;
    }
  } else if (typeof input === 'string') {
    str = input;
  } else {
    return false;
  }

  const trimmed = str.trim();
  return (
    trimmed.startsWith('-----BEGIN PGP ') ||
    trimmed.includes('-----BEGIN PGP ')
  );
}
