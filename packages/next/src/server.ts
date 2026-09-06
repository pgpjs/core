import { Key, decrypt, sign, readKey, readPublicKey, DecryptResult } from '@pgpjs/core';
import PGPJS from '@pgpjs/core';

export interface PGPRouteHandlerContext<T = any> {
  data: T;
  sender?: {
    keyID?: string;
    fingerprint?: string;
    valid: boolean;
  };
  request: Request;
  rawPayload: string;
}

export interface PGPRouteHandlerOptions {
  privateKey?: Key | string;
  passphrase?: string;
  clientPublicKey?: Key | string;
  requireSignature?: boolean;
}

/**
 * Next.js Route Handler middleware that automatically handles:
 * incoming encrypted request -> decrypt -> verify signature -> call handler -> encrypt response.
 */
export function pgp<T = any, R = any>(
  handler: (ctx: PGPRouteHandlerContext<T>) => Promise<R> | R,
  options: PGPRouteHandlerOptions = {}
) {
  return async function POST(request: Request): Promise<Response> {
    const rawPayload = await request.text();
    const serverPrivateKey = options.privateKey ?? process.env.PGP_SERVER_PRIVATE_KEY;
    if (!serverPrivateKey) {
      return new Response(JSON.stringify({ error: 'Server PGP private key is not configured' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const secKey = typeof serverPrivateKey === 'string'
      ? await readKey({ armoredKey: serverPrivateKey })
      : serverPrivateKey;

    if (options.passphrase && !secKey.isDecrypted) {
      await secKey.decrypt(options.passphrase);
    }

    let verificationKeys: Key | undefined;
    if (options.clientPublicKey) {
      verificationKeys = typeof options.clientPublicKey === 'string'
        ? await readPublicKey({ armoredKey: options.clientPublicKey })
        : options.clientPublicKey;
    }

    const decrypted = await decrypt({
      message: rawPayload,
      decryptionKeys: secKey,
      verificationKeys
    });

    const primarySig = decrypted.signatures[0];
    if (options.requireSignature && (!primarySig || !primarySig.valid)) {
      return new Response(JSON.stringify({ error: 'Unauthorized: Invalid or missing client signature' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    let parsedData: T;
    const bodyStr = decrypted.text ?? new TextDecoder().decode(decrypted.data);
    if (bodyStr.startsWith('json:')) {
      parsedData = JSON.parse(bodyStr.slice(5)) as T;
    } else if (bodyStr.startsWith('str:')) {
      parsedData = bodyStr.slice(4) as unknown as T;
    } else if (bodyStr.startsWith('bin:')) {
      parsedData = Buffer.from(bodyStr.slice(4), 'base64') as unknown as T;
    } else {
      try {
        parsedData = JSON.parse(bodyStr) as T;
      } catch {
        parsedData = bodyStr as unknown as T;
      }
    }

    const result = await handler({
      data: parsedData,
      sender: primarySig ? { keyID: primarySig.keyID, fingerprint: primarySig.fingerprint, valid: primarySig.valid } : undefined,
      request,
      rawPayload
    });

    // If client provided a public key, encrypt the response
    if (verificationKeys) {
      const encryptedResponse = await PGPJS.seal(result, {
        to: verificationKeys,
        from: secKey
      });
      return new Response(encryptedResponse as string, {
        status: 200,
        headers: { 'Content-Type': 'application/pgp-encrypted' }
      });
    }

    return new Response(JSON.stringify(result), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  };
}

/**
 * Server-only helper to decrypt encrypted request payloads in Next.js Route Handlers.
 */
export async function decryptInRouteHandler(
  request: Request,
  options: {
    decryptionKeys: Key | Key[];
    passwords?: string[];
  }
): Promise<DecryptResult> {
  const bodyText = await request.text();
  return decrypt({
    message: bodyText,
    decryptionKeys: options.decryptionKeys,
    passwords: options.passwords
  });
}

/**
 * Higher-order helper for Next.js Server Actions to securely decrypt client-submitted encrypted payloads.
 */
export function createServerActionDecrypt(options: {
  privateKey?: string;
  decryptionKeys?: Key | Key[];
  passphrase?: string;
  passwords?: string[];
}) {
  return async function handleDecrypt(encryptedMessage: string): Promise<DecryptResult> {
    let keys = options.decryptionKeys;
    if (!keys && options.privateKey) {
      const k = await readKey({ armoredKey: options.privateKey });
      if (options.passphrase && !k.isDecrypted) {
        await k.decrypt(options.passphrase);
      }
      keys = k;
    }
    return decrypt({
      message: encryptedMessage,
      decryptionKeys: keys,
      passwords: options.passwords
    });
  };
}

/**
 * Higher-order helper for Next.js Server Actions to sign responses before sending to clients.
 */
export function createServerActionSign(options: {
  signingKey?: string;
  signingKeys?: Key | Key[];
  passphrase?: string;
}) {
  return async function handleSign(data: string | Uint8Array, detached: boolean = false): Promise<string | Uint8Array> {
    let keys = options.signingKeys;
    if (!keys && options.signingKey) {
      const k = await readKey({ armoredKey: options.signingKey });
      if (options.passphrase && !k.isDecrypted) {
        await k.decrypt(options.passphrase);
      }
      keys = k;
    }
    return sign({
      message: data,
      signingKeys: keys!,
      detached,
      format: 'armored'
    });
  };
}
