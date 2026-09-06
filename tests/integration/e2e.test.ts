import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  createMessage,
  createCleartextMessage,
  encrypt,
  decrypt,
  sign,
  verify,
  readKey,
  createEncryptStream,
  createDecryptStream,
  PGPDecryptionError
} from '../../packages/core/src/index.js';

describe('End-to-End OpenPGP Operations', () => {
  it('performs full encrypt -> decrypt roundtrip with ECC keys', async () => {
    // 1. Generate keys for Alice and Bob
    const alice = await generateKeyPair({
      type: 'ecc',
      curve: 'ed25519',
      userIDs: ['Alice <alice@example.com>']
    });

    const bob = await generateKeyPair({
      type: 'ecc',
      curve: 'ed25519',
      userIDs: ['Bob <bob@example.com>']
    });

    // 2. Alice creates and encrypts a signed message for Bob
    const secretMessageText = 'Hello Bob, this is a top-secret message from Alice with UTF-8: 🔐🚀';
    const message = await createMessage({ text: secretMessageText });

    const encryptedArmored = await encrypt({
      message,
      encryptionKeys: bob.publicKey,
      signingKeys: alice.privateKey,
      format: 'armored'
    });

    expect(typeof encryptedArmored).toBe('string');
    expect(encryptedArmored).toContain('-----BEGIN PGP MESSAGE-----');

    // 3. Bob decrypts and verifies the message
    const decrypted = await decrypt({
      message: encryptedArmored,
      decryptionKeys: bob.privateKey,
      verificationKeys: alice.publicKey
    });

    expect(decrypted.text).toBe(secretMessageText);
    expect(decrypted.signatures.length).toBe(1);
    expect(decrypted.signatures[0].valid).toBe(true);
    expect(await decrypted.signatures[0].verified).toBe(true);
  }, 15000);

  it('performs full encrypt -> decrypt roundtrip with RSA keys', async () => {
    const alice = await generateKeyPair({
      type: 'rsa',
      rsaBits: 2048,
      userIDs: ['Alice RSA <alice.rsa@example.com>']
    });

    const bob = await generateKeyPair({
      type: 'rsa',
      rsaBits: 2048,
      userIDs: ['Bob RSA <bob.rsa@example.com>']
    });

    const messageText = 'RSA 2048-bit OpenPGP encryption & signing test';
    const encrypted = await encrypt({
      message: messageText,
      encryptionKeys: bob.publicKey,
      signingKeys: alice.privateKey,
      format: 'armored'
    });

    const decrypted = await decrypt({
      message: encrypted,
      decryptionKeys: bob.privateKey,
      verificationKeys: alice.publicKey
    });

    expect(decrypted.text).toBe(messageText);
    expect(decrypted.signatures.length).toBe(1);
    expect(decrypted.signatures[0].valid).toBe(true);
  }, 20000);

  it('supports multi-recipient and passphrase encryption simultaneously', async () => {
    const userA = await generateKeyPair({ userIDs: ['User A <a@example.com>'] });
    const userB = await generateKeyPair({ userIDs: ['User B <b@example.com>'] });
    const sharedPassword = 'shared-symmetric-secret';

    const secretData = 'Confidential report shared with A, B, and passphrase holders';
    const encrypted = await encrypt({
      message: secretData,
      encryptionKeys: [userA.publicKey, userB.publicKey],
      passwords: [sharedPassword]
    });

    // Decrypt with User A
    const decA = await decrypt({ message: encrypted, decryptionKeys: userA.privateKey });
    expect(decA.text).toBe(secretData);

    // Decrypt with User B
    const decB = await decrypt({ message: encrypted, decryptionKeys: userB.privateKey });
    expect(decB.text).toBe(secretData);

    // Decrypt with symmetric password
    const decPwd = await decrypt({ message: encrypted, passwords: [sharedPassword] });
    expect(decPwd.text).toBe(secretData);

    // Wrong password fails with PGPDecryptionError
    await expect(decrypt({ message: encrypted, passwords: ['wrong-password'] })).rejects.toThrow(
      PGPDecryptionError
    );
  }, 15000);

  it('detects tampering and enforces Modification Detection Code (MDC)', async () => {
    const key = await generateKeyPair({ userIDs: ['User <u@example.com>'] });
    const message = 'Integrity protected payload';

    const encrypted = (await encrypt({
      message,
      encryptionKeys: key.publicKey,
      format: 'binary'
    })) as Uint8Array;

    // Tamper with one byte in the ciphertext body
    const tampered = new Uint8Array(encrypted);
    tampered[tampered.length - 25] ^= 0x01;

    await expect(
      decrypt({
        message: tampered,
        decryptionKeys: key.privateKey
      })
    ).rejects.toThrow(PGPDecryptionError);
  }, 10000);

  it('signs and verifies detached signatures', async () => {
    const key = await generateKeyPair({ userIDs: ['Signer <signer@example.com>'] });
    const document = 'Contract terms and conditions: agreed on 2026-09-06.';

    const signature = await sign({
      message: document,
      signingKeys: key.privateKey,
      detached: true
    });

    expect(typeof signature).toBe('string');
    expect(signature).toContain('-----BEGIN PGP SIGNATURE-----');

    // Verify correct document
    const result = await verify({
      message: document,
      signature,
      verificationKeys: key.publicKey
    });
    expect(result.signatures.length).toBe(1);
    expect(result.signatures[0].valid).toBe(true);

    // Verify tampered document fails
    const badResult = await verify({
      message: 'Tampered contract terms',
      signature,
      verificationKeys: key.publicKey
    });
    expect(badResult.signatures[0].valid).toBe(false);
  }, 10000);

  it('signs and verifies cleartext messages', async () => {
    const key = await generateKeyPair({ userIDs: ['Author <author@example.com>'] });
    const text = 'Notice to all employees:\n- The office will be closed on Friday.\n- Have a great weekend!';

    const cleartextSigned = (await sign({
      message: text,
      signingKeys: key.privateKey,
      detached: false,
      format: 'armored'
    })) as string;

    expect(cleartextSigned).toContain('-----BEGIN PGP SIGNED MESSAGE-----');
    expect(cleartextSigned).toContain('Hash: SHA256');
    expect(cleartextSigned).toContain('- - The office will be closed on Friday.');
    expect(cleartextSigned).toContain('-----BEGIN PGP SIGNATURE-----');

    const verified = await verify({
      message: cleartextSigned,
      verificationKeys: key.publicKey
    });

    expect(verified.text).toBe(text);
    expect(verified.signatures.length).toBe(1);
    expect(verified.signatures[0].valid).toBe(true);
  }, 10000);

  it('encrypts and decrypts with Web Streams', async () => {
    const key = await generateKeyPair({ userIDs: ['Streamer <stream@example.com>'] });
    const payload = new TextEncoder().encode('Streamed OpenPGP payload chunks');

    const encStream = createEncryptStream({
      encryptionKeys: key.publicKey
    });

    const encPromise = (async () => {
      const reader = encStream.readable.getReader();
      const chunks: Uint8Array[] = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
      return chunks[0];
    })();

    const writer = encStream.writable.getWriter();
    await writer.write(payload.subarray(0, 10));
    await writer.write(payload.subarray(10));
    await writer.close();

    const encryptedBytes = await encPromise;
    expect(encryptedBytes).toBeDefined();

    // Decrypt stream
    const decStream = createDecryptStream({
      decryptionKeys: key.privateKey
    });

    const decPromise = (async () => {
      const reader = decStream.readable.getReader();
      const chunks: Uint8Array[] = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) chunks.push(value);
      }
      return chunks[0];
    })();

    const decWriter = decStream.writable.getWriter();
    await decWriter.write(encryptedBytes!);
    await decWriter.close();

    const decryptedBytes = await decPromise;
    expect(new TextDecoder().decode(decryptedBytes)).toBe('Streamed OpenPGP payload chunks');
  }, 15000);
});
