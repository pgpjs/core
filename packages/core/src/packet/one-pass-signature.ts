import { Packet } from './packet.js';
import { HashAlgorithm, PacketTag, PublicKeyAlgorithm, SignatureType } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { concatBytes, bytesToHex, hexToBytes } from '../utils/bytes.js';

export class OnePassSignaturePacket extends Packet {
  tag = PacketTag.OnePassSignature;
  version: number = 3;
  signatureType: SignatureType;
  hashAlgorithm: HashAlgorithm;
  publicKeyAlgorithm: PublicKeyAlgorithm;
  issuerKeyID: string; // 16 hex chars
  nested: boolean;

  constructor(options: {
    version?: number;
    signatureType: SignatureType;
    hashAlgorithm: HashAlgorithm;
    publicKeyAlgorithm: PublicKeyAlgorithm;
    issuerKeyID: string;
    nested?: boolean;
  }) {
    super();
    this.version = options.version ?? 3;
    this.signatureType = options.signatureType;
    this.hashAlgorithm = options.hashAlgorithm;
    this.publicKeyAlgorithm = options.publicKeyAlgorithm;
    this.issuerKeyID = options.issuerKeyID.toUpperCase();
    this.nested = options.nested ?? false;
  }

  static parse(buf: Uint8Array): OnePassSignaturePacket {
    if (buf.length < 13) {
      throw new PGPParseError('Buffer too small for OnePassSignature packet');
    }

    const version = buf[0];
    const signatureType = buf[1] as SignatureType;
    const hashAlgorithm = buf[2] as HashAlgorithm;
    const publicKeyAlgorithm = buf[3] as PublicKeyAlgorithm;
    const issuerKeyID = bytesToHex(buf.slice(4, 12)).toUpperCase();
    const nested = buf[12] !== 0;

    return new OnePassSignaturePacket({
      version,
      signatureType,
      hashAlgorithm,
      publicKeyAlgorithm,
      issuerKeyID,
      nested
    });
  }

  write(): Uint8Array {
    return concatBytes(
      new Uint8Array([
        this.version,
        this.signatureType,
        this.hashAlgorithm,
        this.publicKeyAlgorithm
      ]),
      hexToBytes(this.issuerKeyID),
      new Uint8Array([this.nested ? 1 : 0])
    );
  }
}
