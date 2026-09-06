import {
  CompressionAlgorithm,
  HashAlgorithm,
  KeyFlag,
  PublicKeyAlgorithm,
  RevocationReasonCode,
  SignatureType,
  SymmetricKeyAlgorithm
} from '../types/enums.js';
import { GenerateKeyPairOptions, UserID } from '../types/interfaces.js';
import { PublicKeyPacket, PublicSubkeyPacket } from '../packet/public-key.js';
import { SecretKeyPacket, SecretSubkeyPacket } from '../packet/secret-key.js';
import { UserIDPacket } from '../packet/user-id.js';
import { SubpacketBuilder } from '../packet/signature.js';
import { Key, UserEntry } from './key.js';
import { Subkey } from './subkeys.js';
import { generateRSAKeyPair } from '../crypto/rsa.js';
import { generateECCKeyPair } from '../crypto/ecc.js';
import { getUserIDCertificationData, getSubkeyBindingData, signPacket } from './key-signing.js';

function formatUserID(user: UserID | string): string {
  if (typeof user === 'string') {
    return user;
  }
  let result = user.name ?? '';
  if (user.comment) {
    result += ` (${user.comment})`;
  }
  if (user.email) {
    result += ` <${user.email}>`;
  }
  return result.trim();
}

export interface KeyPairResult {
  privateKey: Key;
  publicKey: Key;
  revocationCertificate: string;
}

/**
 * Generates an OpenPGP key pair with primary key, user ID certifications, and subkeys.
 */
export async function generateKeyPair(options: GenerateKeyPairOptions): Promise<KeyPairResult> {
  const type = options.type ?? 'ecc';
  const userIDs = options.userIDs.length > 0 ? options.userIDs : ['PGPJS User <user@pgpjs.dev>'];
  const creationTime = new Date();

  let primarySecret: SecretKeyPacket;
  let primaryPublic: PublicKeyPacket;

  let expirationSeconds: number | undefined;
  if (options.keyExpirationTime) {
    if (options.keyExpirationTime instanceof Date) {
      expirationSeconds = Math.max(0, Math.floor((options.keyExpirationTime.getTime() - creationTime.getTime()) / 1000));
    } else {
      expirationSeconds = options.keyExpirationTime;
    }
  }

  // 1. Generate primary key
  if (type === 'rsa') {
    const bits = options.rsaBits ?? 3072;
    const rsaKeys = await generateRSAKeyPair(bits);
    primaryPublic = new PublicKeyPacket({
      algorithm: PublicKeyAlgorithm.RSA,
      creationTime,
      n: rsaKeys.n,
      e: rsaKeys.e
    });
    primarySecret = new SecretKeyPacket({
      publicKey: primaryPublic,
      d: rsaKeys.d,
      p: rsaKeys.p,
      q: rsaKeys.q,
      u: rsaKeys.u
    });
  } else {
    // ECC primary key: Ed25519 for signing/certifying
    const curve = options.curve === 'p256' ? 'p256' : 'ed25519';
    const ecc = generateECCKeyPair(curve);
    primaryPublic = new PublicKeyPacket({
      algorithm: curve === 'p256' ? PublicKeyAlgorithm.ECDSA : PublicKeyAlgorithm.EdDSA,
      curve,
      publicKey: ecc.publicKey,
      creationTime
    });
    primarySecret = new SecretKeyPacket({
      publicKey: primaryPublic,
      privateKey: ecc.privateKey
    });
  }

  // 2. Build User IDs and self-certifications
  const users: UserEntry[] = [];

  for (let i = 0; i < userIDs.length; i++) {
    const userStr = formatUserID(userIDs[i]);
    const userPacket = new UserIDPacket(userStr);

    const hashedSubpackets = [
      SubpacketBuilder.signatureCreationTime(creationTime),
      SubpacketBuilder.keyFlags(KeyFlag.Certify, KeyFlag.SignData),
      SubpacketBuilder.preferredSymmetricAlgorithms(
        SymmetricKeyAlgorithm.AES256,
        SymmetricKeyAlgorithm.AES192,
        SymmetricKeyAlgorithm.AES128
      ),
      SubpacketBuilder.preferredHashAlgorithms(
        HashAlgorithm.SHA256,
        HashAlgorithm.SHA512,
        HashAlgorithm.SHA384
      ),
      SubpacketBuilder.preferredCompressionAlgorithms(
        CompressionAlgorithm.ZLIB,
        CompressionAlgorithm.ZIP,
        CompressionAlgorithm.Uncompressed
      )
    ];

    if (expirationSeconds !== undefined) {
      hashedSubpackets.push(SubpacketBuilder.keyExpirationTime(expirationSeconds));
    }
    if (i === 0) {
      hashedSubpackets.push(SubpacketBuilder.primaryUserID());
    }

    const unhashedSubpackets = [
      SubpacketBuilder.issuerKeyID(primaryPublic.getKeyID()),
      SubpacketBuilder.issuerFingerprint(primaryPublic.getFingerprintHex())
    ];

    const hashData = getUserIDCertificationData(primaryPublic, userPacket);
    const certSig = signPacket(
      primarySecret,
      SignatureType.PositiveCertification,
      hashData,
      hashedSubpackets,
      unhashedSubpackets,
      HashAlgorithm.SHA256
    );

    users.push({
      user: userPacket,
      selfCertifications: [certSig],
      revocations: [],
      userAttributes: []
    });
  }

  // 3. Generate Subkeys (e.g. Encryption subkey)
  const subkeys: Subkey[] = [];

  if (type === 'rsa') {
    const bits = options.rsaBits ?? 3072;
    const rsaKeys = await generateRSAKeyPair(bits);
    const subPub = new PublicSubkeyPacket({
      algorithm: PublicKeyAlgorithm.RSA,
      creationTime,
      n: rsaKeys.n,
      e: rsaKeys.e
    });
    const subSec = new SecretSubkeyPacket({
      publicKey: subPub,
      d: rsaKeys.d,
      p: rsaKeys.p,
      q: rsaKeys.q,
      u: rsaKeys.u
    });

    const bindingData = getSubkeyBindingData(primaryPublic, subPub);
    const bindingSig = signPacket(
      primarySecret,
      SignatureType.SubkeyBinding,
      bindingData,
      [
        SubpacketBuilder.signatureCreationTime(creationTime),
        SubpacketBuilder.keyFlags(KeyFlag.EncryptCommunications, KeyFlag.EncryptStorage)
      ],
      [SubpacketBuilder.issuerKeyID(primaryPublic.getKeyID())]
    );

    subkeys.push(new Subkey(subSec, bindingSig));
  } else {
    // ECC encryption subkey: Curve25519 (ECDH)
    const curve = options.curve === 'p256' ? 'p256' : 'curve25519';
    const ecc = generateECCKeyPair(curve);
    const subPub = new PublicSubkeyPacket({
      algorithm: PublicKeyAlgorithm.ECDH,
      curve,
      publicKey: ecc.publicKey,
      creationTime,
      kdfHashAlgorithm: HashAlgorithm.SHA256,
      kdfSymmetricAlgorithm: SymmetricKeyAlgorithm.AES256
    });
    const subSec = new SecretSubkeyPacket({
      publicKey: subPub,
      privateKey: ecc.privateKey
    });

    const bindingData = getSubkeyBindingData(primaryPublic, subPub);
    const bindingSig = signPacket(
      primarySecret,
      SignatureType.SubkeyBinding,
      bindingData,
      [
        SubpacketBuilder.signatureCreationTime(creationTime),
        SubpacketBuilder.keyFlags(KeyFlag.EncryptCommunications, KeyFlag.EncryptStorage)
      ],
      [SubpacketBuilder.issuerKeyID(primaryPublic.getKeyID())]
    );

    subkeys.push(new Subkey(subSec, bindingSig));
  }

  // 4. Construct Key object
  const privateKey = new Key({
    primaryKey: primarySecret,
    users,
    subkeys
  });

  // 5. Generate revocation certificate
  const { revocationCertificate } = await privateKey.revoke(
    'Initial revocation certificate generated at key creation',
    RevocationReasonCode.NoReason
  );
  // Clear the revocation from this active key (since this is an offline revocation cert)
  privateKey.revocations = [];

  // 6. Encrypt private key with passphrase if requested
  if (options.passphrase) {
    await privateKey.encrypt(options.passphrase);
  }

  const publicKey = privateKey.toPublic();

  return {
    privateKey,
    publicKey,
    revocationCertificate
  };
}
