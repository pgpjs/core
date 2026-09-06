import { Readable, Writable, Transform } from 'node:stream';
import { EncryptOptions, DecryptOptions, SignOptions, VerifyOptions } from '@pgpjs/core';
import { encrypt, decrypt, sign, verify, concatBytes } from '@pgpjs/core';

/**
 * Creates a Node.js Transform stream that collects chunks and encrypts the output.
 */
export function createNodeEncryptStream(options: Omit<EncryptOptions, 'message'>): Transform {
  const chunks: Buffer[] = [];

  return new Transform({
    transform(chunk, _encoding, callback) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      callback();
    },
    async flush(callback) {
      try {
        const fullBuffer = Buffer.concat(chunks);
        const encrypted = await encrypt({
          ...options,
          message: new Uint8Array(fullBuffer),
          format: options.format ?? 'armored'
        });

        if (typeof encrypted === 'string') {
          this.push(Buffer.from(encrypted, 'utf-8'));
        } else {
          this.push(Buffer.from(encrypted));
        }
        callback();
      } catch (err: any) {
        callback(err);
      }
    }
  });
}

/**
 * Creates a Node.js Transform stream that collects chunks and decrypts the output.
 */
export function createNodeDecryptStream(options: Omit<DecryptOptions, 'message'>): Transform {
  const chunks: Buffer[] = [];

  return new Transform({
    transform(chunk, _encoding, callback) {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      callback();
    },
    async flush(callback) {
      try {
        const fullBuffer = Buffer.concat(chunks);
        const result = await decrypt({
          ...options,
          message: new Uint8Array(fullBuffer)
        });
        this.push(Buffer.from(result.data));
        callback();
      } catch (err: any) {
        callback(err);
      }
    }
  });
}
