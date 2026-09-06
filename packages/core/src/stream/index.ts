import { EncryptOptions, DecryptOptions, SignOptions, VerifyOptions } from '../types/interfaces.js';
import { encrypt } from '../api/encrypt.js';
import { decrypt } from '../api/decrypt.js';
import { sign } from '../api/sign.js';
import { verify } from '../api/verify.js';
import { concatBytes } from '../utils/bytes.js';

/**
 * Creates a TransformStream that collects chunks and encrypts the stream.
 */
export function createEncryptStream(options: Omit<EncryptOptions, 'message'>): TransformStream<Uint8Array, Uint8Array> {
  const chunks: Uint8Array[] = [];

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk) {
      chunks.push(chunk);
    },
    async flush(controller) {
      const allBytes = concatBytes(...chunks);
      const encrypted = await encrypt({
        ...options,
        message: allBytes,
        format: 'binary'
      });
      controller.enqueue(encrypted as Uint8Array);
    }
  });
}

/**
 * Creates a TransformStream that collects chunks and decrypts the stream.
 */
export function createDecryptStream(options: Omit<DecryptOptions, 'message'>): TransformStream<Uint8Array, Uint8Array> {
  const chunks: Uint8Array[] = [];

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk) {
      chunks.push(chunk);
    },
    async flush(controller) {
      const allBytes = concatBytes(...chunks);
      const decrypted = await decrypt({
        ...options,
        message: allBytes
      });
      controller.enqueue(decrypted.data);
    }
  });
}

/**
 * Creates a TransformStream that collects chunks and produces a detached or attached signature.
 */
export function createSignStream(options: Omit<SignOptions, 'message'>): TransformStream<Uint8Array, Uint8Array> {
  const chunks: Uint8Array[] = [];

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk) {
      chunks.push(chunk);
    },
    async flush(controller) {
      const allBytes = concatBytes(...chunks);
      const signature = await sign({
        ...options,
        message: allBytes,
        format: 'binary'
      });
      controller.enqueue(signature as Uint8Array);
    }
  });
}

/**
 * Creates a TransformStream for signature verification.
 */
export function createVerifyStream(options: Omit<VerifyOptions, 'message'>): TransformStream<Uint8Array, Uint8Array> {
  const chunks: Uint8Array[] = [];

  return new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk) {
      chunks.push(chunk);
    },
    async flush(controller) {
      const allBytes = concatBytes(...chunks);
      const result = await verify({
        ...options,
        message: allBytes
      });
      controller.enqueue(result.data);
    }
  });
}

/**
 * Pipes an AsyncIterable of Uint8Array through an async transform.
 */
export async function* asyncIterableToStream(
  iterable: AsyncIterable<Uint8Array>,
  transform: (data: Uint8Array) => Promise<Uint8Array>
): AsyncIterable<Uint8Array> {
  const chunks: Uint8Array[] = [];
  for await (const chunk of iterable) {
    chunks.push(chunk);
  }
  const allBytes = concatBytes(...chunks);
  const result = await transform(allBytes);
  yield result;
}
