import { Packet } from './packet.js';
import { HashAlgorithm, PacketTag, PublicKeyAlgorithm, SymmetricKeyAlgorithm } from '../types/enums.js';
import { PGPDecryptionError, PGPParseError } from '../errors/index.js';
import { PublicKeyPacket, PublicSubkeyPacket } from './public-key.js';
import { S2K, parseS2K } from '../crypto/s2k.js';
import { concatBytes, bytesEqual, writeUint16BE } from '../utils/bytes.js';
import { parseMPI, serializeMPI, mpiToBigInt } from '../utils/mpi.js';
import { getRandomBytes } from '../utils/random.js';
import { hash } from '../crypto/hash.js';
import { encryptRawCFB, decryptRawCFB, getCipherBlockSize, getCipherKeySize } from '../crypto/cfb.js';

export class SecretKeyPacket extends Packet {
  tag: PacketTag = PacketTag.SecretKey;
  publicKey: PublicKeyPacket;

  s2kUsage: number = 0; // 0 = unencrypted, 254 = SHA-1 S2K, 255 = 2-byte checksum S2K
  symmetricAlgorithm?: SymmetricKeyAlgorithm;
  s2k?: S2K;
  iv?: Uint8Array;
  encryptedData?: Uint8Array;

  // Unencrypted secret fields
  isDecrypted: boolean = true;

  // RSA secret fields
  d?: bigint;
  p?: bigint;
  q?: bigint;
  u?: bigint;

  // ECC secret scalar
  privateKey?: Uint8Array;

  constructor(options: {
    tag?: PacketTag;
    publicKey: PublicKeyPacket;
    s2kUsage?: number;
    symmetricAlgorithm?: SymmetricKeyAlgorithm;
    s2k?: S2K;
    iv?: Uint8Array;
    encryptedData?: Uint8Array;
    d?: bigint;
    p?: bigint;
    q?: bigint;
    u?: bigint;
    privateKey?: Uint8Array;
  }) {
    super();
    if (options.tag) this.tag = options.tag;
    this.publicKey = options.publicKey;
    this.s2kUsage = options.s2kUsage ?? 0;
    this.symmetricAlgorithm = options.symmetricAlgorithm;
    this.s2k = options.s2k;
    this.iv = options.iv;
    this.encryptedData = options.encryptedData;
    this.d = options.d;
    this.p = options.p;
    this.q = options.q;
    this.u = options.u;
    this.privateKey = options.privateKey;

    if (this.s2kUsage !== 0 && this.encryptedData) {
      this.isDecrypted = false;
    }
  }

  static parse(buf: Uint8Array, tag: PacketTag = PacketTag.SecretKey): SecretKeyPacket {
    const pubKey = PublicKeyPacket.parse(buf, tag === PacketTag.SecretKey ? PacketTag.PublicKey : PacketTag.PublicSubkey);
    const pubKeyBody = pubKey.write();
    let offset = pubKeyBody.length;

    if (buf.length < offset + 1) {
      throw new PGPParseError('Buffer too small for secret key S2K usage');
    }

    const s2kUsage = buf[offset];
    offset += 1;

    if (s2kUsage === 0) {
      // Unencrypted secret key
      const secretPacket = new SecretKeyPacket({
        tag,
        publicKey: pubKey,
        s2kUsage: 0
      });
      secretPacket.parseSecretMPIs(buf.subarray(offset));
      return secretPacket;
    } else if (s2kUsage === 254 || s2kUsage === 255) {
      if (buf.length < offset + 1) {
        throw new PGPParseError('Buffer too small for symmetric algorithm ID');
      }
      const symmetricAlgorithm = buf[offset] as SymmetricKeyAlgorithm;
      offset += 1;

      const { s2k, bytesRead } = parseS2K(buf, offset);
      offset += bytesRead;

      const blockSize = getCipherBlockSize(symmetricAlgorithm);
      if (buf.length < offset + blockSize) {
        throw new PGPParseError('Buffer too small for secret key IV');
      }
      const iv = buf.slice(offset, offset + blockSize);
      offset += blockSize;

      const encryptedData = buf.slice(offset);

      return new SecretKeyPacket({
        tag,
        publicKey: pubKey,
        s2kUsage,
        symmetricAlgorithm,
        s2k,
        iv,
        encryptedData
      });
    } else {
      // Legacy cipher ID directly
      const symmetricAlgorithm = s2kUsage as SymmetricKeyAlgorithm;
      const blockSize = getCipherBlockSize(symmetricAlgorithm);
      const iv = buf.slice(offset, offset + blockSize);
      offset += blockSize;
      const encryptedData = buf.slice(offset);

      return new SecretKeyPacket({
        tag,
        publicKey: pubKey,
        s2kUsage: 255,
        symmetricAlgorithm,
        iv,
        encryptedData
      });
    }
  }

  private parseSecretMPIs(buf: Uint8Array): void {
    let offset = 0;
    const algo = this.publicKey.algorithm;

    if (
      algo === PublicKeyAlgorithm.RSA ||
      algo === PublicKeyAlgorithm.RSAEncryptOnly ||
      algo === PublicKeyAlgorithm.RSASignOnly
    ) {
      const mpiD = parseMPI(buf, offset);
      offset += mpiD.byteLength;
      const mpiP = parseMPI(buf, offset);
      offset += mpiP.byteLength;
      const mpiQ = parseMPI(buf, offset);
      offset += mpiQ.byteLength;
      const mpiU = parseMPI(buf, offset);
      offset += mpiU.byteLength;

      this.d = mpiToBigInt(mpiD.data);
      this.p = mpiToBigInt(mpiP.data);
      this.q = mpiToBigInt(mpiQ.data);
      this.u = mpiToBigInt(mpiU.data);
    } else if (
      algo === PublicKeyAlgorithm.EdDSA ||
      algo === PublicKeyAlgorithm.ECDSA ||
      algo === PublicKeyAlgorithm.ECDH
    ) {
      const mpiPriv = parseMPI(buf, offset);
      offset += mpiPriv.byteLength;
      this.privateKey = mpiPriv.data;
    }

    this.isDecrypted = true;
  }

  private serializeSecretMPIs(): Uint8Array {
    const algo = this.publicKey.algorithm;
    if (
      algo === PublicKeyAlgorithm.RSA ||
      algo === PublicKeyAlgorithm.RSAEncryptOnly ||
      algo === PublicKeyAlgorithm.RSASignOnly
    ) {
      return concatBytes(
        serializeMPI(this.d!),
        serializeMPI(this.p!),
        serializeMPI(this.q!),
        serializeMPI(this.u!)
      );
    } else if (
      algo === PublicKeyAlgorithm.EdDSA ||
      algo === PublicKeyAlgorithm.ECDSA ||
      algo === PublicKeyAlgorithm.ECDH
    ) {
      return serializeMPI(this.privateKey!);
    } else {
      throw new Error(`Unsupported secret key algorithm: ${algo}`);
    }
  }

  /**
   * Decrypts the secret key using the given passphrase.
   */
  decrypt(passphrase: string): void {
    if (this.isDecrypted) return;

    if (!this.encryptedData || !this.symmetricAlgorithm || !this.iv) {
      throw new PGPDecryptionError('Secret key lacks encrypted data or parameters');
    }

    const keySize = getCipherKeySize(this.symmetricAlgorithm);
    let derivedKey: Uint8Array;

    if (this.s2k) {
      derivedKey = this.s2k.deriveKey(passphrase, keySize);
    } else {
      derivedKey = hash(HashAlgorithm.SHA1, new TextEncoder().encode(passphrase)).subarray(0, keySize);
    }

    const decrypted = decryptRawCFB(this.symmetricAlgorithm, derivedKey, this.iv, this.encryptedData);

    if (this.s2kUsage === 254) {
      if (decrypted.length < 20) {
        throw new PGPDecryptionError('Decrypted secret key payload too small');
      }
      const mpiData = decrypted.subarray(0, decrypted.length - 20);
      const expectedDigest = decrypted.subarray(decrypted.length - 20);
      const actualDigest = hash(HashAlgorithm.SHA1, mpiData);

      if (!bytesEqual(actualDigest, expectedDigest)) {
        throw new PGPDecryptionError('Incorrect passphrase for secret key');
      }
      this.parseSecretMPIs(mpiData);
    } else {
      if (decrypted.length < 2) {
        throw new PGPDecryptionError('Decrypted secret key payload too small');
      }
      const mpiData = decrypted.subarray(0, decrypted.length - 2);
      const expectedSum = (decrypted[decrypted.length - 2] << 8) | decrypted[decrypted.length - 1];

      let actualSum = 0;
      for (let i = 0; i < mpiData.length; i++) {
        actualSum = (actualSum + mpiData[i]) & 0xffff;
      }
      if (actualSum !== expectedSum) {
        throw new PGPDecryptionError('Incorrect passphrase for secret key');
      }
      this.parseSecretMPIs(mpiData);
    }
  }

  /**
   * Encrypts the secret key using a passphrase.
   */
  encrypt(
    passphrase: string,
    s2k?: S2K,
    symmetricAlgorithm: SymmetricKeyAlgorithm = SymmetricKeyAlgorithm.AES256
  ): void {
    if (!this.isDecrypted) {
      throw new Error('Secret key must be decrypted before encrypting');
    }

    this.s2kUsage = 254;
    this.symmetricAlgorithm = symmetricAlgorithm;
    this.s2k = s2k ?? new S2K();

    const keySize = getCipherKeySize(symmetricAlgorithm);
    const derivedKey = this.s2k.deriveKey(passphrase, keySize);

    const mpiData = this.serializeSecretMPIs();
    const digest = hash(HashAlgorithm.SHA1, mpiData);
    const plaintext = concatBytes(mpiData, digest);

    const blockSize = getCipherBlockSize(symmetricAlgorithm);
    this.iv = getRandomBytes(blockSize);
    this.encryptedData = encryptRawCFB(symmetricAlgorithm, derivedKey, this.iv, plaintext);

    // Wipe unencrypted secret fields
    this.d = undefined;
    this.p = undefined;
    this.q = undefined;
    this.u = undefined;
    this.privateKey = undefined;
    this.isDecrypted = false;
  }

  write(): Uint8Array {
    const pubPart = this.publicKey.write();

    if (this.s2kUsage === 0) {
      const secretMPIs = this.serializeSecretMPIs();
      let checksum = 0;
      for (let i = 0; i < secretMPIs.length; i++) {
        checksum = (checksum + secretMPIs[i]) & 0xffff;
      }
      return concatBytes(
        pubPart,
        new Uint8Array([0]),
        secretMPIs,
        writeUint16BE(checksum)
      );
    } else {
      return concatBytes(
        pubPart,
        new Uint8Array([this.s2kUsage, this.symmetricAlgorithm!]),
        this.s2k!.serialize(),
        this.iv!,
        this.encryptedData!
      );
    }
  }
}

export class SecretSubkeyPacket extends SecretKeyPacket {
  override tag: PacketTag = PacketTag.SecretSubkey;

  constructor(options: ConstructorParameters<typeof SecretKeyPacket>[0]) {
    super({ ...options, tag: PacketTag.SecretSubkey });
  }

  static override parse(buf: Uint8Array): SecretSubkeyPacket {
    const sk = SecretKeyPacket.parse(buf, PacketTag.SecretSubkey);
    return new SecretSubkeyPacket({
      tag: PacketTag.SecretSubkey,
      publicKey: new PublicSubkeyPacket({
        version: sk.publicKey.version,
        creationTime: sk.publicKey.creationTime,
        algorithm: sk.publicKey.algorithm,
        n: sk.publicKey.n,
        e: sk.publicKey.e,
        curve: sk.publicKey.curve,
        curveOID: sk.publicKey.curveOID,
        publicKey: sk.publicKey.publicKey,
        kdfHashAlgorithm: sk.publicKey.kdfHashAlgorithm,
        kdfSymmetricAlgorithm: sk.publicKey.kdfSymmetricAlgorithm
      }),
      s2kUsage: sk.s2kUsage,
      symmetricAlgorithm: sk.symmetricAlgorithm,
      s2k: sk.s2k,
      iv: sk.iv,
      encryptedData: sk.encryptedData,
      d: sk.d,
      p: sk.p,
      q: sk.q,
      u: sk.u,
      privateKey: sk.privateKey
    });
  }
}
