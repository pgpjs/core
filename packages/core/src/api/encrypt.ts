import {
  ArmorType,
  CompressionAlgorithm,
  HashAlgorithm,
  PublicKeyAlgorithm,
  SignatureType,
  SymmetricKeyAlgorithm
} from '../types/enums.js';
import { EncryptOptions } from '../types/interfaces.js';
import { PGPEncryptionError } from '../errors/index.js';
import { Message } from '../message/message.js';
import { Key } from '../key/key.js';
import { PacketList } from '../packet/packet-list.js';
import { LiteralDataPacket } from '../packet/literal-data.js';
import { CompressedDataPacket } from '../packet/compressed-data.js';
import { OnePassSignaturePacket } from '../packet/one-pass-signature.js';
import { PublicKeyEncryptedSessionKeyPacket } from '../packet/pkesk.js';
import { SymEncryptedSessionKeyPacket } from '../packet/skesk.js';
import { SymEncryptedIntegrityProtectedDataPacket } from '../packet/sym-encrypted-integrity-protected-data.js';
import { armor } from '../armor/armor.js';
import { concatBytes, writeUint16BE } from '../utils/bytes.js';
import { getRandomBytes } from '../utils/random.js';
import { hash } from '../crypto/hash.js';
import { encryptCFB, encryptRawCFB, getCipherBlockSize, getCipherKeySize } from '../crypto/cfb.js';
import { encryptRSA } from '../crypto/rsa.js';
import { encryptECDH } from '../crypto/ecc.js';
import { S2K } from '../crypto/s2k.js';
import { signPacket } from '../key/key-signing.js';
import { SecretKeyPacket, SecretSubkeyPacket } from '../packet/secret-key.js';
import { PublicKeyPacket } from '../packet/public-key.js';

export async function encrypt(options: EncryptOptions): Promise<string | Uint8Array> {
  let msg: Message;
  if (options.message instanceof Message) {
    msg = options.message;
  } else if (typeof options.message === 'string') {
    msg = Message.fromText(options.message);
  } else if (options.message instanceof Uint8Array) {
    msg = Message.fromBinary(options.message);
  } else {
    throw new PGPEncryptionError('Invalid message parameter provided to encrypt');
  }

  const encryptionKeys: Key[] = options.encryptionKeys
    ? Array.isArray(options.encryptionKeys)
      ? options.encryptionKeys
      : [options.encryptionKeys]
    : [];

  const passwords: string[] = options.passwords
    ? Array.isArray(options.passwords)
      ? options.passwords
      : [options.passwords]
    : [];

  const signingKeys: Key[] = options.signingKeys
    ? Array.isArray(options.signingKeys)
      ? options.signingKeys
      : [options.signingKeys]
    : [];

  if (encryptionKeys.length === 0 && passwords.length === 0) {
    throw new PGPEncryptionError('Encryption requires at least one encryptionKey or password');
  }

  const symmetricAlgorithm = options.symmetricAlgorithm ?? SymmetricKeyAlgorithm.AES256;
  const compression = options.compression ?? CompressionAlgorithm.ZLIB;
  const format = options.format ?? 'armored';

  // 1. Prepare literal data & optional signatures
  const innerPackets = new PacketList();
  const literalData = msg.getLiteralData() ?? new LiteralDataPacket({ data: msg.getBytes() });

  const opsPackets: OnePassSignaturePacket[] = [];
  const sigPackets: any[] = [];

  for (let i = 0; i < signingKeys.length; i++) {
    const key = signingKeys[i];
    const signingKeyPacket = await key.getSigningKey();
    if (!signingKeyPacket || !(signingKeyPacket instanceof SecretKeyPacket || signingKeyPacket instanceof SecretSubkeyPacket)) {
      throw new PGPEncryptionError('Signing key must be an unlocked secret key');
    }

    const pubKey = signingKeyPacket.publicKey;
    const ops = new OnePassSignaturePacket({
      signatureType: SignatureType.BinaryDocument,
      hashAlgorithm: HashAlgorithm.SHA256,
      publicKeyAlgorithm: pubKey.algorithm,
      issuerKeyID: pubKey.getKeyID(),
      nested: i > 0
    });
    opsPackets.push(ops);

    const sig = signPacket(
      signingKeyPacket,
      SignatureType.BinaryDocument,
      literalData.data,
      [],
      [],
      HashAlgorithm.SHA256
    );
    sigPackets.push(sig);
  }

  for (const ops of opsPackets) {
    innerPackets.push(ops);
  }
  innerPackets.push(literalData);
  for (const sig of sigPackets) {
    innerPackets.push(sig);
  }

  let payloadToEncrypt = innerPackets.write();

  // 2. Optional compression
  if (compression !== CompressionAlgorithm.Uncompressed) {
    const compPacket = CompressedDataPacket.fromPackets(payloadToEncrypt, compression);
    payloadToEncrypt = compPacket.serialize();
  }

  // 3. Generate session key
  const sessionKeyLength = getCipherKeySize(symmetricAlgorithm);
  const sessionKey = getRandomBytes(sessionKeyLength);

  const topPackets = new PacketList();

  // 4. Public-key encrypted session keys (PKESK)
  for (const encKey of encryptionKeys) {
    const rawPubPacket = await encKey.getEncryptionKey();
    if (!rawPubPacket) {
      throw new PGPEncryptionError(`No suitable encryption subkey found on key ${encKey.getKeyID()}`);
    }

    const pubPacket: PublicKeyPacket =
      rawPubPacket instanceof SecretKeyPacket ? rawPubPacket.publicKey : rawPubPacket;

    const keyID = pubPacket.getKeyID();
    const pubAlgo = pubPacket.algorithm;

    if (
      pubAlgo === PublicKeyAlgorithm.RSA ||
      pubAlgo === PublicKeyAlgorithm.RSAEncryptOnly
    ) {
      let checksum = 0;
      for (let i = 0; i < sessionKey.length; i++) {
        checksum = (checksum + sessionKey[i]) & 0xffff;
      }
      const rsaPayload = concatBytes(
        new Uint8Array([symmetricAlgorithm]),
        sessionKey,
        writeUint16BE(checksum)
      );

      const encrypted = encryptRSA({ n: pubPacket.n!, e: pubPacket.e! }, rsaPayload);
      topPackets.push(
        new PublicKeyEncryptedSessionKeyPacket({
          keyID,
          publicKeyAlgorithm: pubAlgo,
          encryptedMPI: encrypted
        })
      );
    } else if (pubAlgo === PublicKeyAlgorithm.ECDH) {
      const curve = pubPacket.curve ?? 'curve25519';
      const fp = pubPacket.getFingerprint();
      const { ephemeralPublicKey, wrappedKey } = encryptECDH(
        curve,
        pubPacket.publicKey!,
        fp,
        sessionKey,
        symmetricAlgorithm,
        pubPacket.kdfHashAlgorithm ?? HashAlgorithm.SHA256,
        pubPacket.kdfSymmetricAlgorithm ?? SymmetricKeyAlgorithm.AES128
      );

      topPackets.push(
        new PublicKeyEncryptedSessionKeyPacket({
          keyID,
          publicKeyAlgorithm: pubAlgo,
          ephemeralPublicKey,
          wrappedKey
        })
      );
    } else {
      throw new PGPEncryptionError(`Unsupported public key encryption algorithm: ${pubAlgo}`);
    }
  }

  // 5. Symmetric-key encrypted session keys (SKESK)
  for (const pwd of passwords) {
    const s2k = new S2K({
      type: 3, // Iterated and Salted
      hashAlgorithm: HashAlgorithm.SHA256,
      count: 65536
    });
    const derivedKey = s2k.deriveKey(pwd, sessionKeyLength);
    const blockSize = getCipherBlockSize(symmetricAlgorithm);
    const iv = getRandomBytes(blockSize);

    const keyData = concatBytes(new Uint8Array([symmetricAlgorithm]), sessionKey);
    const encryptedKey = encryptRawCFB(symmetricAlgorithm, derivedKey, iv, keyData);

    topPackets.push(
      new SymEncryptedSessionKeyPacket({
        symmetricAlgorithm,
        s2k,
        encryptedSessionKey: concatBytes(iv, encryptedKey)
      })
    );
  }

  // 6. SEIPD v1 encryption with Modification Detection Code (MDC)
  const blockSize = getCipherBlockSize(symmetricAlgorithm);
  const prefix = getRandomBytes(blockSize);
  const prefixWithCheck = concatBytes(
    prefix,
    new Uint8Array([prefix[blockSize - 2], prefix[blockSize - 1]])
  );

  const mdcTag = new Uint8Array([0xd3, 0x14]);
  const mdcInput = concatBytes(prefixWithCheck, payloadToEncrypt, mdcTag);
  const mdcDigest = hash(HashAlgorithm.SHA1, mdcInput);

  const plainWithMDC = concatBytes(payloadToEncrypt, mdcTag, mdcDigest);
  const ciphertext = encryptCFB(symmetricAlgorithm, sessionKey, plainWithMDC, prefix);

  topPackets.push(
    new SymEncryptedIntegrityProtectedDataPacket({
      version: 1,
      encryptedData: ciphertext
    })
  );

  const binaryResult = topPackets.write();
  if (format === 'binary') {
    return binaryResult;
  }
  return armor(ArmorType.Message, binaryResult);
}
