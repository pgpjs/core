import { Packet } from './packet.js';
import { PacketTag, PublicKeyAlgorithm } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { concatBytes, bytesToHex, hexToBytes } from '../utils/bytes.js';
import { parseMPI, serializeMPI } from '../utils/mpi.js';

export class PublicKeyEncryptedSessionKeyPacket extends Packet {
  tag = PacketTag.PublicKeyEncryptedSessionKey;
  version: number = 3;
  keyID: string; // 16 hex characters
  publicKeyAlgorithm: PublicKeyAlgorithm;

  // RSA encrypted session key MPI
  encryptedMPI?: Uint8Array;

  // ECDH encrypted session key fields
  ephemeralPublicKey?: Uint8Array;
  wrappedKey?: Uint8Array;

  constructor(options: {
    version?: number;
    keyID: string;
    publicKeyAlgorithm: PublicKeyAlgorithm;
    encryptedMPI?: Uint8Array;
    ephemeralPublicKey?: Uint8Array;
    wrappedKey?: Uint8Array;
  }) {
    super();
    this.version = options.version ?? 3;
    this.keyID = options.keyID.toUpperCase();
    this.publicKeyAlgorithm = options.publicKeyAlgorithm;
    this.encryptedMPI = options.encryptedMPI;
    this.ephemeralPublicKey = options.ephemeralPublicKey;
    this.wrappedKey = options.wrappedKey;
  }

  static parse(buf: Uint8Array): PublicKeyEncryptedSessionKeyPacket {
    if (buf.length < 10) {
      throw new PGPParseError('Buffer too small for PKESK packet');
    }

    const version = buf[0];
    const keyID = bytesToHex(buf.slice(1, 9)).toUpperCase();
    const publicKeyAlgorithm = buf[9] as PublicKeyAlgorithm;
    let offset = 10;

    if (
      publicKeyAlgorithm === PublicKeyAlgorithm.RSA ||
      publicKeyAlgorithm === PublicKeyAlgorithm.RSAEncryptOnly
    ) {
      const mpi = parseMPI(buf, offset);
      return new PublicKeyEncryptedSessionKeyPacket({
        version,
        keyID,
        publicKeyAlgorithm,
        encryptedMPI: mpi.data
      });
    } else if (publicKeyAlgorithm === PublicKeyAlgorithm.ECDH) {
      const ephMPI = parseMPI(buf, offset);
      offset += ephMPI.byteLength;

      if (buf.length < offset + 1) {
        throw new PGPParseError('Buffer too small for ECDH wrapped key length');
      }
      const wrappedKeyLen = buf[offset++];
      const wrappedKey = buf.slice(offset, offset + wrappedKeyLen);

      return new PublicKeyEncryptedSessionKeyPacket({
        version,
        keyID,
        publicKeyAlgorithm,
        ephemeralPublicKey: ephMPI.data,
        wrappedKey
      });
    } else {
      throw new PGPParseError(`Unsupported public key algorithm for PKESK: ${publicKeyAlgorithm}`);
    }
  }

  write(): Uint8Array {
    const header = concatBytes(
      new Uint8Array([this.version]),
      hexToBytes(this.keyID),
      new Uint8Array([this.publicKeyAlgorithm])
    );

    if (
      this.publicKeyAlgorithm === PublicKeyAlgorithm.RSA ||
      this.publicKeyAlgorithm === PublicKeyAlgorithm.RSAEncryptOnly
    ) {
      return concatBytes(header, serializeMPI(this.encryptedMPI!));
    } else if (this.publicKeyAlgorithm === PublicKeyAlgorithm.ECDH) {
      return concatBytes(
        header,
        serializeMPI(this.ephemeralPublicKey!),
        new Uint8Array([this.wrappedKey!.length]),
        this.wrappedKey!
      );
    } else {
      throw new Error(`Cannot write PKESK for algorithm: ${this.publicKeyAlgorithm}`);
    }
  }
}
