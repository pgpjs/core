import { SymmetricKeyAlgorithm } from "../../types/enums.js";
import { PGPAlgorithmError, PGPDecryptionError } from "../../errors/index.js";
import { getRandomBytes } from "../random/index.js";
import { getCipherBlockSize, createBlockEncryptor, getCipherKeySize } from "../symmetric/index.js";

export { getCipherBlockSize, getCipherKeySize };

/**
 * OpenPGP CFB mode encryption (RFC 4880 Section 13.9, RFC 9580 Section 11.4).
 */
export function encryptCFB(
  algorithm: SymmetricKeyAlgorithm,
  key: Uint8Array,
  plaintext: Uint8Array,
  prefix?: Uint8Array,
  resync: boolean = true
): Uint8Array {
  const blockSize = getCipherBlockSize(algorithm);
  const encryptBlock = createBlockEncryptor(algorithm, key);

  let pfx: Uint8Array;
  if (prefix) {
    if (prefix.length === blockSize) {
      pfx = new Uint8Array(blockSize + 2);
      pfx.set(prefix, 0);
      pfx[blockSize] = prefix[blockSize - 2];
      pfx[blockSize + 1] = prefix[blockSize - 1];
    } else if (prefix.length === blockSize + 2) {
      pfx = prefix;
    } else {
      throw new PGPAlgorithmError(`Invalid prefix length: ${prefix.length}`);
    }
  } else {
    const randomBytes = getRandomBytes(blockSize);
    pfx = new Uint8Array(blockSize + 2);
    pfx.set(randomBytes, 0);
    pfx[blockSize] = randomBytes[blockSize - 2];
    pfx[blockSize + 1] = randomBytes[blockSize - 1];
  }

  const ciphertext = new Uint8Array(pfx.length + plaintext.length);
  let fr: Uint8Array<any> = new Uint8Array(blockSize); // IV all zeroes
  let fre = encryptBlock(fr);

  for (let i = 0; i < blockSize; i++) {
    ciphertext[i] = pfx[i] ^ fre[i];
  }

  fr = ciphertext.subarray(0, blockSize);
  fre = encryptBlock(fr);

  ciphertext[blockSize] = pfx[blockSize] ^ fre[0];
  ciphertext[blockSize + 1] = pfx[blockSize + 1] ^ fre[1];

  if (resync) {
    fr = ciphertext.subarray(2, blockSize + 2);
  } else {
    fr = ciphertext.subarray(0, blockSize);
  }
  fre = encryptBlock(fr);

  let outPos = blockSize + 2;
  let inPos = 0;
  let frePos = resync ? 0 : 2;

  while (inPos < plaintext.length) {
    if (frePos === blockSize) {
      fr = ciphertext.subarray(outPos - blockSize, outPos);
      fre = encryptBlock(fr);
      frePos = 0;
    }
    ciphertext[outPos++] = plaintext[inPos++] ^ fre[frePos++];
  }

  return ciphertext;
}

/**
 * OpenPGP CFB mode decryption (RFC 4880 Section 13.9, RFC 9580 Section 11.4).
 */
export function decryptCFB(
  algorithm: SymmetricKeyAlgorithm,
  key: Uint8Array,
  ciphertext: Uint8Array,
  resync: boolean = true
): Uint8Array {
  const blockSize = getCipherBlockSize(algorithm);
  const encryptBlock = createBlockEncryptor(algorithm, key);

  if (ciphertext.length < blockSize + 2) {
    throw new PGPDecryptionError("Ciphertext is too short for OpenPGP CFB prefix");
  }

  let fr: Uint8Array<any> = new Uint8Array(blockSize);
  let fre = encryptBlock(fr);

  const prefix = new Uint8Array(blockSize + 2);
  for (let i = 0; i < blockSize; i++) {
    prefix[i] = ciphertext[i] ^ fre[i];
  }

  fr = ciphertext.subarray(0, blockSize);
  fre = encryptBlock(fr);

  prefix[blockSize] = ciphertext[blockSize] ^ fre[0];
  prefix[blockSize + 1] = ciphertext[blockSize + 1] ^ fre[1];

  if (
    prefix[blockSize] !== prefix[blockSize - 2] ||
    prefix[blockSize + 1] !== prefix[blockSize - 1]
  ) {
    throw new PGPDecryptionError("OpenPGP CFB prefix check failed (resync mismatch)");
  }

  if (resync) {
    fr = ciphertext.subarray(2, blockSize + 2);
  } else {
    fr = ciphertext.subarray(0, blockSize);
  }
  fre = encryptBlock(fr);

  const plaintextLength = ciphertext.length - (blockSize + 2);
  const plaintext = new Uint8Array(plaintextLength);

  let inPos = blockSize + 2;
  let outPos = 0;
  let frePos = resync ? 0 : 2;

  while (outPos < plaintextLength) {
    if (frePos === blockSize) {
      fr = ciphertext.subarray(inPos - blockSize, inPos);
      fre = encryptBlock(fr);
      frePos = 0;
    }
    plaintext[outPos++] = ciphertext[inPos++] ^ fre[frePos++];
  }

  return plaintext;
}

export function encryptRawCFB(
  algorithm: SymmetricKeyAlgorithm,
  key: Uint8Array,
  iv: Uint8Array,
  plaintext: Uint8Array
): Uint8Array {
  const blockSize = getCipherBlockSize(algorithm);
  const encryptBlock = createBlockEncryptor(algorithm, key);

  let fr: Uint8Array<any> = new Uint8Array(blockSize);
  fr.set(iv.subarray(0, blockSize));

  const ciphertext = new Uint8Array(plaintext.length);
  let fre = encryptBlock(fr);
  let frePos = 0;

  for (let i = 0; i < plaintext.length; i++) {
    if (frePos === blockSize) {
      fr = ciphertext.subarray(i - blockSize, i);
      fre = encryptBlock(fr);
      frePos = 0;
    }
    ciphertext[i] = plaintext[i] ^ fre[frePos++];
  }

  return ciphertext;
}

export function decryptRawCFB(
  algorithm: SymmetricKeyAlgorithm,
  key: Uint8Array,
  iv: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  const blockSize = getCipherBlockSize(algorithm);
  const encryptBlock = createBlockEncryptor(algorithm, key);

  let fr: Uint8Array<any> = new Uint8Array(blockSize);
  fr.set(iv.subarray(0, blockSize));

  const plaintext = new Uint8Array(ciphertext.length);
  let fre = encryptBlock(fr);
  let frePos = 0;

  for (let i = 0; i < ciphertext.length; i++) {
    if (frePos === blockSize) {
      fr = ciphertext.subarray(i - blockSize, i);
      fre = encryptBlock(fr);
      frePos = 0;
    }
    plaintext[i] = ciphertext[i] ^ fre[frePos++];
  }

  return plaintext;
}
