import { HashAlgorithm, S2KType } from "../../types/enums.js";
import { PGPParseError, PGPAlgorithmError } from "../../errors/index.js";
import { getRandomBytes } from "../random/index.js";
import { deriveSimpleS2K } from "./simple.js";
import { deriveSaltedS2K } from "./salted.js";
import { decodeS2KCount, encodeS2KCount, deriveIteratedS2K } from "./iterated.js";
import { deriveArgon2S2K } from "./argon2.js";

export { decodeS2KCount, encodeS2KCount };
export { deriveSimpleS2K } from "./simple.js";
export { deriveSaltedS2K } from "./salted.js";
export { deriveIteratedS2K } from "./iterated.js";
export { deriveArgon2S2K } from "./argon2.js";

export class S2K {
  type: S2KType;
  hashAlgorithm: HashAlgorithm;
  salt?: Uint8Array;
  count?: number;
  encodedCount?: number;
  argon2Passes?: number;
  argon2MemoryExponent?: number;
  argon2Parallelism?: number;

  constructor(options: {
    type?: S2KType;
    hashAlgorithm?: HashAlgorithm;
    salt?: Uint8Array;
    count?: number;
    encodedCount?: number;
    argon2Passes?: number;
    argon2MemoryExponent?: number;
    argon2Parallelism?: number;
  } = {}) {
    this.type = options.type ?? S2KType.IteratedAndSalted;
    this.hashAlgorithm = options.hashAlgorithm ?? HashAlgorithm.SHA256;
    this.salt = options.salt;

    if (this.type === S2KType.Salted || this.type === S2KType.IteratedAndSalted) {
      if (!this.salt) {
        this.salt = getRandomBytes(8);
      }
    } else if (this.type === S2KType.Argon2) {
      if (!this.salt) {
        this.salt = getRandomBytes(16);
      }
      this.argon2Passes = options.argon2Passes ?? 3;
      this.argon2MemoryExponent = options.argon2MemoryExponent ?? 16;
      this.argon2Parallelism = options.argon2Parallelism ?? 4;
    }

    if (this.type === S2KType.IteratedAndSalted) {
      if (options.count !== undefined) {
        this.count = options.count;
        this.encodedCount = options.encodedCount ?? encodeS2KCount(options.count);
      } else if (options.encodedCount !== undefined) {
        this.encodedCount = options.encodedCount;
        this.count = decodeS2KCount(options.encodedCount);
      } else {
        this.encodedCount = 224;
        this.count = decodeS2KCount(224);
      }
    }
  }

  deriveKey(passphrase: string, keySize: number): Uint8Array {
    return this.produceSessionKey(passphrase, keySize);
  }

  produceSessionKey(passphrase: string, keySize: number): Uint8Array {
    switch (this.type) {
      case S2KType.Simple:
        return deriveSimpleS2K(passphrase, keySize, this.hashAlgorithm);

      case S2KType.Salted:
        if (!this.salt) throw new PGPAlgorithmError("Salted S2K requires salt");
        return deriveSaltedS2K(passphrase, this.salt, keySize, this.hashAlgorithm);

      case S2KType.IteratedAndSalted:
        if (!this.salt || this.count === undefined) {
          throw new PGPAlgorithmError("Iterated & Salted S2K requires salt and iteration count");
        }
        return deriveIteratedS2K(passphrase, this.salt, this.count, keySize, this.hashAlgorithm);

      case S2KType.Argon2:
        if (!this.salt) throw new PGPAlgorithmError("Argon2 S2K requires 16-byte salt");
        return deriveArgon2S2K(passphrase, this.salt, keySize, {
          passes: this.argon2Passes,
          memoryExponent: this.argon2MemoryExponent,
          parallelism: this.argon2Parallelism
        });

      default:
        throw new PGPAlgorithmError(`Unsupported S2K type: ${this.type}`);
    }
  }

  serialize(): Uint8Array {
    switch (this.type) {
      case S2KType.Simple:
        return new Uint8Array([this.type, this.hashAlgorithm]);

      case S2KType.Salted:
        if (!this.salt || this.salt.length !== 8) {
          throw new PGPAlgorithmError("Salted S2K requires 8-byte salt");
        }
        const saltedOut = new Uint8Array(10);
        saltedOut[0] = this.type;
        saltedOut[1] = this.hashAlgorithm;
        saltedOut.set(this.salt, 2);
        return saltedOut;

      case S2KType.IteratedAndSalted:
        if (!this.salt || this.salt.length !== 8) {
          throw new PGPAlgorithmError("Iterated & Salted S2K requires 8-byte salt");
        }
        const iterOut = new Uint8Array(11);
        iterOut[0] = this.type;
        iterOut[1] = this.hashAlgorithm;
        iterOut.set(this.salt, 2);
        iterOut[10] = this.encodedCount ?? 224;
        return iterOut;

      case S2KType.Argon2:
        if (!this.salt || this.salt.length !== 16) {
          throw new PGPAlgorithmError("Argon2 S2K requires 16-byte salt");
        }
        const argonOut = new Uint8Array(20);
        argonOut[0] = this.type;
        argonOut.set(this.salt, 1);
        argonOut[17] = this.argon2Passes ?? 3;
        argonOut[18] = this.argon2Parallelism ?? 4;
        argonOut[19] = this.argon2MemoryExponent ?? 16;
        return argonOut;

      default:
        throw new PGPAlgorithmError(`Cannot serialize S2K type ${this.type}`);
    }
  }
}

export function parseS2K(bytes: Uint8Array, offset: number = 0): { s2k: S2K; bytesRead: number } {
  const buf = offset > 0 ? bytes.subarray(offset) : bytes;
  if (buf.length < 2) {
    throw new PGPParseError("Insufficient bytes for S2K header");
  }

  const type = buf[0] as S2KType;

  switch (type) {
    case S2KType.Simple:
      return {
        s2k: new S2K({ type, hashAlgorithm: buf[1] as HashAlgorithm }),
        bytesRead: 2
      };

    case S2KType.Salted:
      if (buf.length < 10) throw new PGPParseError("Insufficient bytes for Salted S2K");
      return {
        s2k: new S2K({
          type,
          hashAlgorithm: buf[1] as HashAlgorithm,
          salt: buf.subarray(2, 10)
        }),
        bytesRead: 10
      };

    case S2KType.IteratedAndSalted:
      if (buf.length < 11) throw new PGPParseError("Insufficient bytes for Iterated & Salted S2K");
      return {
        s2k: new S2K({
          type,
          hashAlgorithm: buf[1] as HashAlgorithm,
          salt: buf.subarray(2, 10),
          encodedCount: buf[10],
          count: decodeS2KCount(buf[10])
        }),
        bytesRead: 11
      };

    case S2KType.Argon2:
      if (buf.length < 20) throw new PGPParseError("Insufficient bytes for Argon2 S2K");
      return {
        s2k: new S2K({
          type,
          salt: buf.subarray(1, 17),
          argon2Passes: buf[17],
          argon2Parallelism: buf[18],
          argon2MemoryExponent: buf[19]
        }),
        bytesRead: 20
      };

    default:
      throw new PGPParseError(`Unknown S2K type: ${type}`);
  }
}

