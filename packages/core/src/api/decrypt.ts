import {
  PacketTag,
  PublicKeyAlgorithm,
  SymmetricKeyAlgorithm
} from '../types/enums.js';
import { DecryptOptions, DecryptResult, VerifiedSignature } from '../types/interfaces.js';
import { PGPDecryptionError } from '../errors/index.js';
import { Message } from '../message/message.js';
import { Key } from '../key/key.js';
import { parsePackets } from '../packet/parser.js';
import { dearmor, isArmored } from '../armor/armor.js';
import { PublicKeyEncryptedSessionKeyPacket } from '../packet/pkesk.js';
import { SymEncryptedSessionKeyPacket } from '../packet/skesk.js';
import { SymEncryptedIntegrityProtectedDataPacket } from '../packet/sym-encrypted-integrity-protected-data.js';
import { SymEncryptedDataPacket } from '../packet/sym-encrypted-data.js';
import { CompressedDataPacket } from '../packet/compressed-data.js';
import { LiteralDataPacket } from '../packet/literal-data.js';
import { SignaturePacket } from '../packet/signature.js';
import { decryptCFB, decryptRawCFB, getCipherBlockSize, getCipherKeySize } from '../crypto/cfb.js';
import { decryptRSA } from '../crypto/rsa.js';
import { decryptECDH } from '../crypto/ecc.js';
import { bytesEqual, bytesToUtf8, concatBytes } from '../utils/bytes.js';
import { hash } from '../crypto/hash.js';
import { verifySignaturePacket } from '../key/key-signing.js';
import { SecretKeyPacket, SecretSubkeyPacket } from '../packet/secret-key.js';
import { PublicKeyPacket } from '../packet/public-key.js';

export async function decrypt(options: DecryptOptions): Promise<DecryptResult> {
  let binary: Uint8Array;

  if (options.message instanceof Message) {
    binary = options.message.toBinary();
  } else if (typeof options.message === 'string') {
    if (isArmored(options.message)) {
      binary = dearmor(options.message).data;
    } else {
      throw new PGPDecryptionError('String message passed to decrypt must be ASCII armored');
    }
  } else if (options.message instanceof Uint8Array) {
    if (isArmored(options.message)) {
      binary = dearmor(new TextDecoder().decode(options.message)).data;
    } else {
      binary = options.message;
    }
  } else {
    throw new PGPDecryptionError('Invalid message type provided to decrypt');
  }

  const packets = parsePackets(binary);
  const pkeskPackets = packets.filterByTag<PublicKeyEncryptedSessionKeyPacket>(PacketTag.PublicKeyEncryptedSessionKey);
  const skeskPackets = packets.filterByTag<SymEncryptedSessionKeyPacket>(PacketTag.SymEncryptedSessionKey);
  const seipdPacket = packets.find<SymEncryptedIntegrityProtectedDataPacket>((p) => p.tag === PacketTag.SymEncryptedIntegrityProtectedData);
  const sedPacket = packets.find<SymEncryptedDataPacket>((p) => p.tag === PacketTag.SymEncryptedData);

  if (!seipdPacket && !sedPacket) {
    throw new PGPDecryptionError('Message does not contain encrypted data packet');
  }

  const decryptionKeys: Key[] = options.decryptionKeys
    ? Array.isArray(options.decryptionKeys)
      ? options.decryptionKeys
      : [options.decryptionKeys]
    : [];

  const passwords: string[] = options.passwords
    ? Array.isArray(options.passwords)
      ? options.passwords
      : [options.passwords]
    : [];

  const verificationKeys: Key[] = options.verificationKeys
    ? Array.isArray(options.verificationKeys)
      ? options.verificationKeys
      : [options.verificationKeys]
    : [];

  let sessionKey: Uint8Array | null = null;
  let symmetricAlgorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES256;

  // 1. Try public-key decryption
  for (const pkesk of pkeskPackets) {
    for (const key of decryptionKeys) {
      const candidates: (SecretKeyPacket | SecretSubkeyPacket)[] = [];
      for (const sub of key.getSubkeys()) {
        if (sub.keyPacket instanceof SecretSubkeyPacket) {
          candidates.push(sub.keyPacket);
        }
      }
      if (key.primaryKey instanceof SecretKeyPacket) {
        candidates.push(key.primaryKey);
      }

      for (const secKey of candidates) {
        const keyID = secKey.publicKey.getKeyID();
        if (pkesk.keyID !== '0000000000000000' && keyID !== pkesk.keyID) {
          continue;
        }

        if (!secKey.isDecrypted && passwords.length > 0) {
          for (const pwd of passwords) {
            try {
              secKey.decrypt(pwd);
              if (secKey.isDecrypted) break;
            } catch {
              // ignore
            }
          }
        }

        if (!secKey.isDecrypted) {
          continue;
        }

        try {
          if (
            secKey.publicKey.algorithm === PublicKeyAlgorithm.RSA ||
            secKey.publicKey.algorithm === PublicKeyAlgorithm.RSAEncryptOnly
          ) {
            const decryptedPayload = decryptRSA(
              {
                n: secKey.publicKey.n!,
                e: secKey.publicKey.e!,
                d: secKey.d!,
                p: secKey.p,
                q: secKey.q,
                u: secKey.u
              },
              pkesk.encryptedMPI!
            );

            const decryptedAlgo = decryptedPayload[0] as SymmetricKeyAlgorithm;
            const keySize = getCipherKeySize(decryptedAlgo);
            const candidateKey = decryptedPayload.subarray(1, 1 + keySize);

            const expectedChecksum = (decryptedPayload[decryptedPayload.length - 2] << 8) | decryptedPayload[decryptedPayload.length - 1];
            let actualChecksum = 0;
            for (let i = 0; i < candidateKey.length; i++) {
              actualChecksum = (actualChecksum + candidateKey[i]) & 0xffff;
            }
            if (actualChecksum === expectedChecksum) {
              sessionKey = candidateKey;
              symmetricAlgorithm = decryptedAlgo;
              break;
            }
          } else if (secKey.publicKey.algorithm === PublicKeyAlgorithm.ECDH) {
            const curve = secKey.publicKey.curve ?? 'curve25519';
            const fp = secKey.publicKey.getFingerprint();
            const res = decryptECDH(
              curve,
              secKey.privateKey!,
              fp,
              pkesk.ephemeralPublicKey!,
              pkesk.wrappedKey!,
              secKey.publicKey.kdfHashAlgorithm,
              secKey.publicKey.kdfSymmetricAlgorithm
            );
            sessionKey = res.sessionKey;
            symmetricAlgorithm = res.symmetricAlgorithm;
            break;
          }
        } catch {
          // continue searching other keys
        }
      }
      if (sessionKey) break;
    }
    if (sessionKey) break;
  }

  // 2. Try symmetric password decryption
  if (!sessionKey) {
    for (const skesk of skeskPackets) {
      for (const pwd of passwords) {
        try {
          const keySize = getCipherKeySize(skesk.symmetricAlgorithm);
          const derivedKey = skesk.s2k.deriveKey(pwd, keySize);

          if (skesk.encryptedSessionKey && skesk.encryptedSessionKey.length > 0) {
            const blockSize = getCipherBlockSize(skesk.symmetricAlgorithm);
            const iv = skesk.encryptedSessionKey.subarray(0, blockSize);
            const encKey = skesk.encryptedSessionKey.subarray(blockSize);

            const decryptedKeyData = decryptRawCFB(skesk.symmetricAlgorithm, derivedKey, iv, encKey);
            const decryptedAlgo = decryptedKeyData[0] as SymmetricKeyAlgorithm;
            if (decryptedAlgo !== skesk.symmetricAlgorithm) {
              continue; // Wrong password, try next
            }
            symmetricAlgorithm = decryptedAlgo;
            sessionKey = decryptedKeyData.subarray(1);
            break;
          } else {
            try {
              if (seipdPacket) {
                decryptCFB(skesk.symmetricAlgorithm, derivedKey, seipdPacket.encryptedData);
              }
              sessionKey = derivedKey;
              symmetricAlgorithm = skesk.symmetricAlgorithm;
              break;
            } catch {
              continue;
            }
          }
        } catch {
          // ignore
        }
      }
      if (sessionKey) break;
    }
  }

  if (!sessionKey) {
    throw new PGPDecryptionError('Could not decrypt session key: no valid private key or password available');
  }

  // 3. Decrypt ciphertext
  let decryptedPayload: Uint8Array;

  try {
    if (seipdPacket) {
      const blockSize = getCipherBlockSize(symmetricAlgorithm);
      const decryptedRaw = decryptCFB(symmetricAlgorithm, sessionKey, seipdPacket.encryptedData);

      if (decryptedRaw.length < 22) {
        throw new PGPDecryptionError('Decrypted SEIPD data too short for MDC');
      }

      const payloadLength = decryptedRaw.length - 22;
      const mdcHeader = decryptedRaw.subarray(payloadLength, payloadLength + 2);
      if (mdcHeader[0] !== 0xd3 || mdcHeader[1] !== 0x14) {
        throw new PGPDecryptionError('Invalid MDC packet tag in SEIPD packet');
      }

      const expectedDigest = decryptedRaw.subarray(payloadLength + 2);
      const recoveredPrefix = new Uint8Array(blockSize);
      const encryptBlock = (await import('../crypto/cfb.js')).createBlockEncryptor(symmetricAlgorithm, sessionKey);
      const fre0 = encryptBlock(new Uint8Array(blockSize));
      for (let i = 0; i < blockSize; i++) {
        recoveredPrefix[i] = seipdPacket.encryptedData[i] ^ fre0[i];
      }
      const prefixWithCheck = concatBytes(
        recoveredPrefix,
        new Uint8Array([recoveredPrefix[blockSize - 2], recoveredPrefix[blockSize - 1]])
      );

      decryptedPayload = decryptedRaw.subarray(0, payloadLength);
      const actualDigest = hash(2, concatBytes(prefixWithCheck, decryptedPayload, mdcHeader));

      if (!bytesEqual(actualDigest, expectedDigest)) {
        throw new PGPDecryptionError('Modification Detection Code (MDC) verification failed: message has been tampered with');
      }
    } else if (sedPacket) {
      decryptedPayload = decryptCFB(symmetricAlgorithm, sessionKey, sedPacket.encryptedData);
    } else {
      throw new PGPDecryptionError('No encrypted payload packet found');
    }
  } catch (err: any) {
    if (err instanceof PGPDecryptionError) {
      throw err;
    }
    throw new PGPDecryptionError(`Decryption failed: ${err.message}`, { cause: err });
  }

  // 4. Parse inner packets
  let innerPackets = parsePackets(decryptedPayload);

  const compPacket = innerPackets.find<CompressedDataPacket>((p) => p.tag === PacketTag.CompressedData);
  if (compPacket) {
    const decompressed = compPacket.decompress();
    innerPackets = parsePackets(decompressed);
  }

  const literalData = innerPackets.find<LiteralDataPacket>((p) => p.tag === PacketTag.LiteralData);
  if (!literalData) {
    throw new PGPDecryptionError('Decrypted payload does not contain a LiteralData packet');
  }

  const data = literalData.data;
  let text: string | undefined;
  try {
    text = bytesToUtf8(data);
  } catch {
    text = undefined;
  }
  const filename = literalData.filename;
  const date = literalData.date;

  // 5. Verify attached signatures
  const signatures: VerifiedSignature[] = [];
  const sigPackets = innerPackets.filterByTag<SignaturePacket>(PacketTag.Signature);

  for (const sig of sigPackets) {
    const keyID = sig.getIssuerKeyID() ?? '';
    let verified = false;
    let matchingKey: PublicKeyPacket | undefined;

    for (const vKey of verificationKeys) {
      if (vKey.getKeyID() === keyID) {
        matchingKey = vKey.primaryKey instanceof SecretKeyPacket ? vKey.primaryKey.publicKey : vKey.primaryKey;
        break;
      }
      for (const sub of vKey.getSubkeys()) {
        if (sub.getKeyID() === keyID) {
          matchingKey = sub.keyPacket instanceof SecretSubkeyPacket ? sub.keyPacket.publicKey : sub.keyPacket;
          break;
        }
      }
      if (matchingKey) break;
    }

    if (matchingKey) {
      verified = verifySignaturePacket(matchingKey, sig, data);
    }

    signatures.push({
      keyID,
      valid: verified,
      verified: Promise.resolve(verified),
      signature: sig
    });
  }

  return {
    data,
    text,
    filename,
    date,
    signatures,
    encrypted: true
  };
}
