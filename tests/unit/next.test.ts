import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '@pgpjs/core';
import {
  encryptForServer,
  verifyFromServer,
  createServerActionDecrypt,
  createServerActionSign,
  decryptInRouteHandler
} from '../../packages/next/src/index.js';

describe('@pgpjs/next server/client isolation', () => {
  it('encrypts client data for server and decrypts in server action', async () => {
    const serverKey = await generateKeyPair({ userIDs: ['Server <server@app.com>'] });
    const serverPubArmored = await serverKey.publicKey.armor();

    const clientSecretPayload = JSON.stringify({ userId: 12345, token: 'xyz-secret-token' });

    // Client side: encrypts using server public key
    const encrypted = await encryptForServer(clientSecretPayload, serverPubArmored);
    expect(encrypted).toContain('-----BEGIN PGP MESSAGE-----');

    // Server action side: decrypts
    const serverDecryptAction = createServerActionDecrypt({
      decryptionKeys: serverKey.privateKey
    });

    const decrypted = await serverDecryptAction(encrypted);
    expect(decrypted.text).toBe(clientSecretPayload);
  });

  it('rejects private key passed into encryptForServer to guard against client leaks', async () => {
    const key = await generateKeyPair({ userIDs: ['Leak Test <leak@app.com>'] });

    await expect(encryptForServer('secret', key.privateKey)).rejects.toThrow(
      'Security violation: private key must never be used in client bundle'
    );
  });

  it('decrypts encrypted payload in Next.js Route Handler request', async () => {
    const serverKey = await generateKeyPair({ userIDs: ['API Route <api@app.com>'] });
    const encrypted = await encryptForServer('Route handler body payload', serverKey.publicKey);

    const mockRequest = new Request('https://example.com/api/pgp', {
      method: 'POST',
      body: encrypted,
      headers: { 'Content-Type': 'application/pgp-encrypted' }
    });

    const result = await decryptInRouteHandler(mockRequest, {
      decryptionKeys: serverKey.privateKey
    });

    expect(result.text).toBe('Route handler body payload');
  });

  it('signs in server action and verifies on client', async () => {
    const serverKey = await generateKeyPair({ userIDs: ['Signer <sig@app.com>'] });
    const signAction = createServerActionSign({ signingKeys: serverKey.privateKey });

    const responseData = 'Authenticated server response data';
    const signedMessage = (await signAction(responseData, false)) as string;

    const verifyResult = await verifyFromServer(signedMessage, serverKey.publicKey);
    expect(verifyResult.text).toBe(responseData);
    expect(verifyResult.signatures[0].valid).toBe(true);
  });
});
