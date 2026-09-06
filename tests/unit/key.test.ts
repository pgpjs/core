import { describe, it, expect } from 'vitest';
import {
  generateKeyPair,
  readKey,
  readKeys,
  readPublicKey,
  readPrivateKey,
  revokeKey
} from '../../packages/core/src/key/index.js';

describe('Key Generation & Management', () => {
  it('generates ECC keypair with subkeys and certifications', async () => {
    const { privateKey, publicKey, revocationCertificate } = await generateKeyPair({
      type: 'ecc',
      curve: 'ed25519',
      userIDs: [{ name: 'Alice', email: 'alice@example.com' }]
    });

    expect(privateKey.isPrivate()).toBe(true);
    expect(publicKey.isPrivate()).toBe(false);
    expect(privateKey.getFingerprint()).toBe(publicKey.getFingerprint());
    expect(privateKey.getKeyID()).toBe(publicKey.getKeyID());

    const userIDs = publicKey.getUserIDs();
    expect(userIDs.length).toBe(1);
    expect(userIDs[0]).toBe('Alice <alice@example.com>');

    const subkeys = publicKey.getSubkeys();
    expect(subkeys.length).toBe(1);
    expect(subkeys[0].canEncrypt()).toBe(true);

    expect(typeof revocationCertificate).toBe('string');
    expect(revocationCertificate).toContain('-----BEGIN PGP PUBLIC KEY BLOCK-----');
  }, 10000);

  it('armors and reads keys back accurately', async () => {
    const { privateKey, publicKey } = await generateKeyPair({
      type: 'ecc',
      curve: 'ed25519',
      userIDs: ['Bob <bob@example.com>']
    });

    const pubArmored = await publicKey.armor();
    expect(pubArmored).toContain('-----BEGIN PGP PUBLIC KEY BLOCK-----');

    const privArmored = await privateKey.armor();
    expect(privArmored).toContain('-----BEGIN PGP PRIVATE KEY BLOCK-----');

    const parsedPub = await readPublicKey({ armoredKey: pubArmored });
    expect(parsedPub.isPrivate()).toBe(false);
    expect(parsedPub.getFingerprint()).toBe(publicKey.getFingerprint());
    expect(parsedPub.getUserIDs()).toEqual(['Bob <bob@example.com>']);

    const parsedPriv = await readPrivateKey({ armoredKey: privArmored });
    expect(parsedPriv.isPrivate()).toBe(true);
    expect(parsedPriv.getFingerprint()).toBe(privateKey.getFingerprint());
  }, 10000);

  it('protects private key with passphrase', async () => {
    const { privateKey } = await generateKeyPair({
      type: 'ecc',
      curve: 'ed25519',
      userIDs: ['Charlie <charlie@example.com>'],
      passphrase: 'strong-passphrase'
    });

    const privArmored = await privateKey.armor();
    const parsedPriv = await readPrivateKey({ armoredKey: privArmored });

    // Trying to get signing key without decrypting
    const secPacket = (parsedPriv.primaryKey as any);
    expect(secPacket.isDecrypted).toBe(false);

    // Wrong password fails
    await expect(parsedPriv.decrypt('wrong-password')).rejects.toThrow();

    // Correct password succeeds
    await parsedPriv.decrypt('strong-passphrase');
    expect(secPacket.isDecrypted).toBe(true);
  }, 10000);

  it('applies revocation certificate', async () => {
    const { publicKey, revocationCertificate } = await generateKeyPair({
      type: 'ecc',
      curve: 'ed25519',
      userIDs: ['Dave <dave@example.com>']
    });

    expect(publicKey.isRevoked()).toBe(false);
    await revokeKey({ key: publicKey, revocationCertificate });
    expect(publicKey.isRevoked()).toBe(true);
  }, 10000);

  it('reads multiple keys from armored collection', async () => {
    const key1 = await generateKeyPair({ userIDs: ['User 1 <u1@example.com>'] });
    const key2 = await generateKeyPair({ userIDs: ['User 2 <u2@example.com>'] });

    const combinedArmored = (await key1.publicKey.armor()) + '\n\n' + (await key2.publicKey.armor());
    const keys = await readKeys({ armoredKeys: combinedArmored });

    expect(keys.length).toBe(2);
    expect(keys[0].getFingerprint()).toBe(key1.publicKey.getFingerprint());
    expect(keys[1].getFingerprint()).toBe(key2.publicKey.getFingerprint());
  }, 15000);
});
