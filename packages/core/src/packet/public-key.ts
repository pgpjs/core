import { Packet } from './packet.js';
import { HashAlgorithm, PacketTag, PublicKeyAlgorithm, SymmetricKeyAlgorithm } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { concatBytes, bytesToHex, readUint32BE, writeUint32BE, writeUint16BE } from '../utils/bytes.js';
import { parseMPI, serializeMPI, mpiToBigInt } from '../utils/mpi.js';
import { hash } from '../crypto/hash.js';
import { CURVE_OIDS, getCurveNameByOID } from '../crypto/ecc.js';

export class PublicKeyPacket extends Packet {
  tag: PacketTag = PacketTag.PublicKey;
  version: number = 4;
  creationTime: Date;
  algorithm: PublicKeyAlgorithm;

  // RSA fields
  n?: bigint;
  e?: bigint;

  // ECC fields
  curve?: string;
  curveOID?: Uint8Array;
  publicKey?: Uint8Array; // Raw or prefixed point bytes

  // ECDH KDF parameters
  kdfHashAlgorithm?: HashAlgorithm;
  kdfSymmetricAlgorithm?: SymmetricKeyAlgorithm;

  constructor(options: {
    tag?: PacketTag;
    version?: number;
    creationTime?: Date;
    algorithm: PublicKeyAlgorithm;
    n?: bigint;
    e?: bigint;
    curve?: string;
    curveOID?: Uint8Array;
    publicKey?: Uint8Array;
    kdfHashAlgorithm?: HashAlgorithm;
    kdfSymmetricAlgorithm?: SymmetricKeyAlgorithm;
  }) {
    super();
    if (options.tag) this.tag = options.tag;
    this.version = options.version ?? 4;
    this.creationTime = options.creationTime ?? new Date();
    this.algorithm = options.algorithm;
    this.n = options.n;
    this.e = options.e;
    this.curve = options.curve;
    this.curveOID = options.curveOID;
    this.publicKey = options.publicKey;
    this.kdfHashAlgorithm = options.kdfHashAlgorithm;
    this.kdfSymmetricAlgorithm = options.kdfSymmetricAlgorithm;

    if (this.curve && !this.curveOID) {
      this.curveOID = CURVE_OIDS[this.curve];
    } else if (this.curveOID && !this.curve) {
      this.curve = getCurveNameByOID(this.curveOID);
    }
  }

  static parse(buf: Uint8Array, tag: PacketTag = PacketTag.PublicKey): PublicKeyPacket {
    if (buf.length < 6) {
      throw new PGPParseError('Buffer too small for public key packet');
    }

    const version = buf[0];
    if (version !== 4) {
      throw new PGPParseError(`Unsupported key packet version: ${version}`);
    }

    const timestamp = readUint32BE(buf, 1);
    const creationTime = new Date(timestamp * 1000);
    const algorithm = buf[5] as PublicKeyAlgorithm;

    let offset = 6;

    if (
      algorithm === PublicKeyAlgorithm.RSA ||
      algorithm === PublicKeyAlgorithm.RSAEncryptOnly ||
      algorithm === PublicKeyAlgorithm.RSASignOnly
    ) {
      const mpiN = parseMPI(buf, offset);
      offset += mpiN.byteLength;
      const mpiE = parseMPI(buf, offset);

      return new PublicKeyPacket({
        tag,
        version,
        creationTime,
        algorithm,
        n: mpiToBigInt(mpiN.data),
        e: mpiToBigInt(mpiE.data)
      });
    } else if (
      algorithm === PublicKeyAlgorithm.ECDSA ||
      algorithm === PublicKeyAlgorithm.EdDSA ||
      algorithm === PublicKeyAlgorithm.ECDH
    ) {
      if (buf.length < offset + 1) {
        throw new PGPParseError('Buffer too small for curve OID length');
      }
      const oidLen = buf[offset];
      offset += 1;
      const curveOID = buf.slice(offset, offset + oidLen);
      offset += oidLen;

      const pubMPI = parseMPI(buf, offset);
      offset += pubMPI.byteLength;
      const publicKey = pubMPI.data;

      let kdfHashAlgorithm: HashAlgorithm | undefined;
      let kdfSymmetricAlgorithm: SymmetricKeyAlgorithm | undefined;

      if (algorithm === PublicKeyAlgorithm.ECDH) {
        if (buf.length < offset + 4) {
          throw new PGPParseError('Buffer too small for ECDH KDF parameters');
        }
        const kdfLen = buf[offset];
        offset += 1;
        // buf[offset] is reserved (0x01)
        kdfHashAlgorithm = buf[offset + 1] as HashAlgorithm;
        kdfSymmetricAlgorithm = buf[offset + 2] as SymmetricKeyAlgorithm;
        offset += kdfLen;
      }

      return new PublicKeyPacket({
        tag,
        version,
        creationTime,
        algorithm,
        curveOID,
        publicKey,
        kdfHashAlgorithm,
        kdfSymmetricAlgorithm
      });
    } else {
      throw new PGPParseError(`Unsupported public key algorithm: ${algorithm}`);
    }
  }

  write(): Uint8Array {
    const timestamp = Math.floor(this.creationTime.getTime() / 1000);
    const header = concatBytes(
      new Uint8Array([this.version]),
      writeUint32BE(timestamp),
      new Uint8Array([this.algorithm])
    );

    if (
      this.algorithm === PublicKeyAlgorithm.RSA ||
      this.algorithm === PublicKeyAlgorithm.RSAEncryptOnly ||
      this.algorithm === PublicKeyAlgorithm.RSASignOnly
    ) {
      const mpiN = serializeMPI(this.n!);
      const mpiE = serializeMPI(this.e!);
      return concatBytes(header, mpiN, mpiE);
    } else if (
      this.algorithm === PublicKeyAlgorithm.ECDSA ||
      this.algorithm === PublicKeyAlgorithm.EdDSA ||
      this.algorithm === PublicKeyAlgorithm.ECDH
    ) {
      const oid = this.curveOID ?? CURVE_OIDS[this.curve!];
      const oidPart = concatBytes(new Uint8Array([oid.length]), oid);
      const pubMPI = serializeMPI(this.publicKey!);

      let kdfPart = new Uint8Array(0);
      if (this.algorithm === PublicKeyAlgorithm.ECDH) {
        kdfPart = new Uint8Array([
          3, // 3 octets follow
          1, // reserved 0x01
          this.kdfHashAlgorithm ?? HashAlgorithm.SHA256,
          this.kdfSymmetricAlgorithm ?? SymmetricKeyAlgorithm.AES128
        ]);
      }

      return concatBytes(header, oidPart, pubMPI, kdfPart);
    } else {
      throw new Error(`Cannot write unsupported public key algorithm: ${this.algorithm}`);
    }
  }

  /**
   * Computes RFC 4880 §12.2 v4 SHA-1 20-byte fingerprint.
   */
  getFingerprint(): Uint8Array {
    const body = this.write();
    const prefix = concatBytes(
      new Uint8Array([0x99]),
      writeUint16BE(body.length),
      body
    );
    return hash(HashAlgorithm.SHA1, prefix);
  }

  /**
   * Returns 40-character uppercase hexadecimal fingerprint.
   */
  getFingerprintHex(): string {
    return bytesToHex(this.getFingerprint()).toUpperCase();
  }

  /**
   * Returns low 8 octets (16 hex chars) Key ID.
   */
  getKeyID(): string {
    const fp = this.getFingerprint();
    return bytesToHex(fp.subarray(12, 20)).toUpperCase();
  }
}

export class PublicSubkeyPacket extends PublicKeyPacket {
  override tag: PacketTag = PacketTag.PublicSubkey;

  constructor(options: ConstructorParameters<typeof PublicKeyPacket>[0]) {
    super({ ...options, tag: PacketTag.PublicSubkey });
  }

  static override parse(buf: Uint8Array): PublicSubkeyPacket {
    const pk = PublicKeyPacket.parse(buf, PacketTag.PublicSubkey);
    return new PublicSubkeyPacket({
      version: pk.version,
      creationTime: pk.creationTime,
      algorithm: pk.algorithm,
      n: pk.n,
      e: pk.e,
      curve: pk.curve,
      curveOID: pk.curveOID,
      publicKey: pk.publicKey,
      kdfHashAlgorithm: pk.kdfHashAlgorithm,
      kdfSymmetricAlgorithm: pk.kdfSymmetricAlgorithm
    });
  }
}
