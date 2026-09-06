import { HashAlgorithm, PublicKeyAlgorithm, SignatureType } from '../types/enums.js';
import { PublicKeyPacket } from '../packet/public-key.js';
import { SecretKeyPacket } from '../packet/secret-key.js';
import { SignaturePacket, SignatureSubpacket, SubpacketBuilder } from '../packet/signature.js';
import { UserIDPacket } from '../packet/user-id.js';
import { concatBytes, writeUint16BE, writeUint32BE } from '../utils/bytes.js';
import { hash } from '../crypto/hash.js';
import { signRSA, verifyRSA } from '../crypto/rsa.js';
import { signECC, verifyECC } from '../crypto/ecc.js';
import { PGPSignatureError } from '../errors/index.js';

/**
 * Signs data using RSA or ECC secret key.
 */
export function createSignatureBytes(
  signer: SecretKeyPacket,
  hashAlgorithm: HashAlgorithm,
  digest: Uint8Array
): { hashPrefix: Uint8Array; signatureData: Uint8Array[] } {
  if (!signer.isDecrypted) {
    throw new PGPSignatureError('Signer key must be decrypted to produce signatures');
  }

  const hashPrefix = digest.slice(0, 2);
  const pubAlgo = signer.publicKey.algorithm;

  if (
    pubAlgo === PublicKeyAlgorithm.RSA ||
    pubAlgo === PublicKeyAlgorithm.RSASignOnly
  ) {
    const sigBytes = signRSA(
      {
        n: signer.publicKey.n!,
        e: signer.publicKey.e!,
        d: signer.d!,
        p: signer.p,
        q: signer.q,
        u: signer.u
      },
      hashAlgorithm,
      digest
    );
    return { hashPrefix, signatureData: [sigBytes] };
  } else if (
    pubAlgo === PublicKeyAlgorithm.EdDSA ||
    pubAlgo === PublicKeyAlgorithm.ECDSA
  ) {
    const curve = signer.publicKey.curve ?? 'ed25519';
    const { r, s } = signECC(curve, signer.privateKey!, digest);
    return { hashPrefix, signatureData: [r, s] };
  } else {
    throw new PGPSignatureError(`Unsupported algorithm for signing: ${pubAlgo}`);
  }
}

/**
 * Verifies signature over digest using RSA or ECC public key.
 */
export function verifySignatureBytes(
  verifier: PublicKeyPacket,
  hashAlgorithm: HashAlgorithm,
  digest: Uint8Array,
  signatureData: Uint8Array[]
): boolean {
  const pubAlgo = verifier.algorithm;

  if (
    pubAlgo === PublicKeyAlgorithm.RSA ||
    pubAlgo === PublicKeyAlgorithm.RSASignOnly
  ) {
    if (signatureData.length < 1) return false;
    return verifyRSA(
      { n: verifier.n!, e: verifier.e! },
      hashAlgorithm,
      digest,
      signatureData[0]
    );
  } else if (
    pubAlgo === PublicKeyAlgorithm.EdDSA ||
    pubAlgo === PublicKeyAlgorithm.ECDSA
  ) {
    if (signatureData.length < 2) return false;
    const curve = verifier.curve ?? 'ed25519';
    return verifyECC(curve, verifier.publicKey!, digest, signatureData[0], signatureData[1]);
  } else {
    return false;
  }
}

/**
 * Computes signature trailer suffix per RFC 4880 §5.2.4:
 * 0x04 || 0xFF || 4-octet big-endian length of trailer data
 */
export function getTrailerSuffix(trailerLength: number): Uint8Array {
  return concatBytes(new Uint8Array([0x04, 0xff]), writeUint32BE(trailerLength));
}

/**
 * Signs an OpenPGP packet or data structure into a SignaturePacket.
 */
export function signPacket(
  signer: SecretKeyPacket,
  signatureType: SignatureType,
  dataToHash: Uint8Array,
  hashedSubpackets: SignatureSubpacket[] = [],
  unhashedSubpackets: SignatureSubpacket[] = [],
  hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256
): SignaturePacket {
  // Ensure issuer key ID is present
  const keyId = signer.publicKey.getKeyID();
  const hasIssuer = hashedSubpackets.some((s) => s.type === 16) || unhashedSubpackets.some((s) => s.type === 16);
  if (!hasIssuer) {
    unhashedSubpackets.push(SubpacketBuilder.issuerKeyID(keyId));
  }

  // Ensure creation time is present
  const hasTime = hashedSubpackets.some((s) => s.type === 2);
  if (!hasTime) {
    hashedSubpackets.push(SubpacketBuilder.signatureCreationTime(new Date()));
  }

  const sigPacket = new SignaturePacket({
    signatureType,
    publicKeyAlgorithm: signer.publicKey.algorithm,
    hashAlgorithm,
    hashedSubpackets,
    unhashedSubpackets
  });

  const trailer = sigPacket.getSignatureTrailer();
  const trailerSuffix = getTrailerSuffix(trailer.length);

  const fullHashInput = concatBytes(dataToHash, trailer, trailerSuffix);
  const digest = hash(hashAlgorithm, fullHashInput);

  const { hashPrefix, signatureData } = createSignatureBytes(signer, hashAlgorithm, digest);
  sigPacket.hashPrefix = hashPrefix;
  sigPacket.signatureData = signatureData;

  return sigPacket;
}

/**
 * Verifies a SignaturePacket against the given data.
 */
export function verifySignaturePacket(
  verifier: PublicKeyPacket,
  signature: SignaturePacket,
  dataToHash: Uint8Array
): boolean {
  const trailer = signature.getSignatureTrailer();
  const trailerSuffix = getTrailerSuffix(trailer.length);

  const fullHashInput = concatBytes(dataToHash, trailer, trailerSuffix);
  const digest = hash(signature.hashAlgorithm, fullHashInput);

  // Quick check prefix
  if (
    digest[0] !== signature.hashPrefix[0] ||
    digest[1] !== signature.hashPrefix[1]
  ) {
    return false;
  }

  return verifySignatureBytes(verifier, signature.hashAlgorithm, digest, signature.signatureData);
}

/**
 * Creates User ID certification hash data:
 * 0x99 || 2-octet length || pubkey body || 0xB4 || 4-octet length || userid
 */
export function getUserIDCertificationData(primaryPub: PublicKeyPacket, user: UserIDPacket): Uint8Array {
  const pubBody = primaryPub.write();
  const userBody = user.write();

  return concatBytes(
    new Uint8Array([0x99]),
    writeUint16BE(pubBody.length),
    pubBody,
    new Uint8Array([0xb4]),
    writeUint32BE(userBody.length),
    userBody
  );
}

/**
 * Creates Subkey Binding hash data:
 * 0x99 || 2-octet length || primary pubkey body || 0x99 || 2-octet length || subkey pubkey body
 */
export function getSubkeyBindingData(primaryPub: PublicKeyPacket, subkeyPub: PublicKeyPacket): Uint8Array {
  const primBody = primaryPub.write();
  const subBody = subkeyPub.write();

  return concatBytes(
    new Uint8Array([0x99]),
    writeUint16BE(primBody.length),
    primBody,
    new Uint8Array([0x99]),
    writeUint16BE(subBody.length),
    subBody
  );
}

/**
 * Creates Direct Key / Key Revocation hash data:
 * 0x99 || 2-octet length || pubkey body
 */
export function getKeyRevocationData(pubKey: PublicKeyPacket): Uint8Array {
  const pubBody = pubKey.write();
  return concatBytes(new Uint8Array([0x99]), writeUint16BE(pubBody.length), pubBody);
}
