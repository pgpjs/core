import { HashAlgorithm } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { getHashName, getHashAlgorithmByName } from '../crypto/hash.js';

export interface CleartextMessageData {
  text: string;
  normalizedText: string;
  signatureArmor: string;
  hashAlgorithm: HashAlgorithm;
}

/**
 * Normalizes cleartext document for signing/verification per RFC 4880 §7.1.
 * - Converts newlines to \r\n
 * - Strips trailing whitespace on each line
 * - Omits trailing newline on the final line for hashing
 */
export function canonicalizeCleartext(text: string): string {
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  const normalizedLines = lines.map((line) => line.replace(/[ \t]+$/, ''));
  return normalizedLines.join('\r\n');
}

/**
 * Formats a signed cleartext message.
 */
export function formatCleartextSignedMessage(
  text: string,
  signatureArmor: string,
  hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256
): string {
  const hashName = getHashName(hashAlgorithm);
  let result = `-----BEGIN PGP SIGNED MESSAGE-----\r\n`;
  result += `Hash: ${hashName}\r\n\r\n`;

  // Dash-escape lines beginning with '-'
  const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.startsWith('-')) {
      result += `- ${line}\r\n`;
    } else {
      result += `${line}\r\n`;
    }
  }

  result += signatureArmor.trim() + '\r\n';
  return result;
}

/**
 * Parses an ASCII armored cleartext signed message.
 */
export function parseCleartextSignedMessage(armored: string): CleartextMessageData {
  const sigHeader = '-----BEGIN PGP SIGNATURE-----';
  const sigIndex = armored.indexOf(sigHeader);

  if (sigIndex === -1) {
    throw new PGPParseError('Cleartext signed message missing PGP SIGNATURE block');
  }

  const messagePart = armored.slice(0, sigIndex);
  const signatureArmor = armored.slice(sigIndex);

  const lines = messagePart.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');

  let startIndex = -1;
  let hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === '-----BEGIN PGP SIGNED MESSAGE-----') {
      startIndex = i;
      break;
    }
  }

  if (startIndex === -1) {
    throw new PGPParseError('Missing -----BEGIN PGP SIGNED MESSAGE----- header');
  }

  let bodyStartIndex = -1;
  for (let i = startIndex + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') {
      bodyStartIndex = i + 1;
      break;
    }
    if (line.startsWith('Hash:')) {
      const algoName = line.slice(5).trim();
      hashAlgorithm = getHashAlgorithmByName(algoName);
    }
  }

  if (bodyStartIndex === -1) {
    throw new PGPParseError('Malformed cleartext signed message header');
  }

  const textLines: string[] = [];
  for (let i = bodyStartIndex; i < lines.length; i++) {
    let line = lines[i];
    // Remove dash-escape if line starts with '- '
    if (line.startsWith('- ')) {
      line = line.slice(2);
    }
    textLines.push(line);
  }

  // Remove any trailing empty line before the signature header
  while (textLines.length > 0 && textLines[textLines.length - 1].trim() === '') {
    textLines.pop();
  }

  const text = textLines.join('\n');
  const normalizedText = canonicalizeCleartext(text);

  return {
    text,
    normalizedText,
    signatureArmor,
    hashAlgorithm
  };
}
