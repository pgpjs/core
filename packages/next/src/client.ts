import { Key, readPublicKey, readKey, encrypt, verify, VerifyResult } from '@pgpjs/core';

/**
 * Client-safe helper to encrypt data intended for the server.
 * Never takes or requires private keys.
 */
export async function encryptForServer(
  message: string | Uint8Array,
  serverPublicKey: Key | string
): Promise<string> {
  const pubKey = typeof serverPublicKey === 'string'
    ? await readPublicKey({ armoredKey: serverPublicKey })
    : serverPublicKey;

  if (pubKey.isPrivate()) {
    throw new Error('Security violation: private key must never be used in client bundle');
  }

  const encrypted = await encrypt({
    message,
    encryptionKeys: pubKey,
    format: 'armored'
  });

  return encrypted as string;
}

/**
 * Client-safe helper to verify server-signed responses.
 */
export async function verifyFromServer(
  message: string | Uint8Array,
  serverPublicKey: Key | string,
  signature?: string
): Promise<VerifyResult> {
  const pubKey = typeof serverPublicKey === 'string'
    ? await readPublicKey({ armoredKey: serverPublicKey })
    : serverPublicKey;

  return verify({
    message,
    signature,
    verificationKeys: pubKey
  });
}

export interface SecureRequestOptions {
  url: string;
  body: any;
  encryptWith: Key | string;
  signWith?: Key | string;
  passphrase?: string;
  fetchOptions?: RequestInit;
}

/**
 * Client-safe helper that encrypts and optionally signs a payload, transmits it to an API route,
 * and parses the response.
 */
export async function secureRequest<T = any>(options: SecureRequestOptions): Promise<T> {
  const pubKey = typeof options.encryptWith === 'string'
    ? await readPublicKey({ armoredKey: options.encryptWith })
    : options.encryptWith;

  let signingKey: Key | undefined;
  if (options.signWith) {
    signingKey = typeof options.signWith === 'string'
      ? await readKey({ armoredKey: options.signWith })
      : options.signWith;
    if (options.passphrase && !signingKey.isDecrypted) {
      await signingKey.decrypt(options.passphrase);
    }
  }

  const payload = typeof options.body === 'string' ? options.body : JSON.stringify(options.body);

  const encrypted = await encrypt({
    message: payload,
    encryptionKeys: pubKey,
    signingKeys: signingKey,
    format: 'armored'
  });

  const response = await fetch(options.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/pgp-encrypted',
      ...(options.fetchOptions?.headers || {})
    },
    body: encrypted as string,
    ...options.fetchOptions
  });

  const resText = await response.text();
  try {
    return JSON.parse(resText) as T;
  } catch {
    return resText as unknown as T;
  }
}
