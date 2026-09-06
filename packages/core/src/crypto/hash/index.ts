import { sha1 } from '@noble/hashes/sha1';
import { sha224, sha256 } from '@noble/hashes/sha256';
import { sha384, sha512 } from '@noble/hashes/sha512';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { HashAlgorithm } from '../../types/enums.js';
import { PGPAlgorithmError } from '../../errors/index.js';
import { hexToBytes } from '../../utils/bytes.js';

export function getHasher(algorithm: HashAlgorithm) {
  switch (algorithm) {
    case HashAlgorithm.SHA256:
      return sha256;
    case HashAlgorithm.SHA512:
      return sha512;
    case HashAlgorithm.SHA384:
      return sha384;
    case HashAlgorithm.SHA224:
      return sha224;
    case HashAlgorithm.SHA1:
      return sha1;
    case HashAlgorithm.RIPEMD160:
      return ripemd160;
    default:
      throw new PGPAlgorithmError(`Unsupported hash algorithm ID: ${algorithm}`);
  }
}

export function getHash(algorithm: HashAlgorithm): (data: Uint8Array) => Uint8Array {
  return (data: Uint8Array) => getHasher(algorithm)(data);
}


export function hash(algorithm: HashAlgorithm, data: Uint8Array): Uint8Array {
  return getHash(algorithm)(data);
}

export function getHashDigestLength(algorithm: HashAlgorithm): number {
  switch (algorithm) {
    case HashAlgorithm.SHA256:
      return 32;
    case HashAlgorithm.SHA512:
      return 64;
    case HashAlgorithm.SHA384:
      return 48;
    case HashAlgorithm.SHA224:
      return 28;
    case HashAlgorithm.SHA1:
    case HashAlgorithm.RIPEMD160:
      return 20;
    default:
      throw new PGPAlgorithmError(`Unsupported hash algorithm ID: ${algorithm}`);
  }
}

export function getHashName(algorithm: HashAlgorithm): string {
  switch (algorithm) {
    case HashAlgorithm.SHA256:
      return 'SHA256';
    case HashAlgorithm.SHA512:
      return 'SHA512';
    case HashAlgorithm.SHA384:
      return 'SHA384';
    case HashAlgorithm.SHA224:
      return 'SHA224';
    case HashAlgorithm.SHA1:
      return 'SHA1';
    case HashAlgorithm.RIPEMD160:
      return 'RIPEMD160';
    default:
      return `UNKNOWN (${algorithm})`;
  }
}

export function getHashAlgorithmByName(name: string): HashAlgorithm {
  const upper = name.toUpperCase().replace(/[-_]/g, '');
  switch (upper) {
    case 'SHA256':
      return HashAlgorithm.SHA256;
    case 'SHA512':
      return HashAlgorithm.SHA512;
    case 'SHA384':
      return HashAlgorithm.SHA384;
    case 'SHA224':
      return HashAlgorithm.SHA224;
    case 'SHA1':
      return HashAlgorithm.SHA1;
    case 'RIPEMD160':
      return HashAlgorithm.RIPEMD160;
    default:
      throw new PGPAlgorithmError(`Unknown hash algorithm name: ${name}`);
  }
}

/**
 * RFC 4880 / RFC 3447 ASN.1 DigestInfo prefixes for RSASSA-PKCS1-v1_5.
 */
export const HASH_DIGEST_INFO_PREFIXES: Record<number, Uint8Array> = {
  [HashAlgorithm.SHA1]: hexToBytes('3021300906052b0e03021a05000414'),
  [HashAlgorithm.RIPEMD160]: hexToBytes('3021300906052b2403020105000414'),
  [HashAlgorithm.SHA224]: hexToBytes('302d300d06096086480165030402040500041c'),
  [HashAlgorithm.SHA256]: hexToBytes('3031300d060960864801650304020105000420'),
  [HashAlgorithm.SHA384]: hexToBytes('3041300d060960864801650304020205000430'),
  [HashAlgorithm.SHA512]: hexToBytes('3051300d060960864801650304020305000440')
};
