import { PGPError } from '../errors/index.js';

export function getRandomBytes(count: number): Uint8Array {
  if (count < 0) {
    throw new PGPError(`Invalid random byte count: ${count}`);
  }
  const bytes = new Uint8Array(count);
  if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  }
  throw new PGPError('Secure random number generator (crypto.getRandomValues) is not available');
}
