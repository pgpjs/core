import { Packet } from './packet.js';
import { PacketTag, SymmetricKeyAlgorithm } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { S2K, parseS2K } from '../crypto/s2k.js';
import { concatBytes } from '../utils/bytes.js';

export class SymEncryptedSessionKeyPacket extends Packet {
  tag = PacketTag.SymEncryptedSessionKey;
  version: number = 4;
  symmetricAlgorithm: SymmetricKeyAlgorithm;
  s2k: S2K;
  encryptedSessionKey?: Uint8Array;

  constructor(options: {
    version?: number;
    symmetricAlgorithm: SymmetricKeyAlgorithm;
    s2k: S2K;
    encryptedSessionKey?: Uint8Array;
  }) {
    super();
    this.version = options.version ?? 4;
    this.symmetricAlgorithm = options.symmetricAlgorithm;
    this.s2k = options.s2k;
    this.encryptedSessionKey = options.encryptedSessionKey;
  }

  static parse(buf: Uint8Array): SymEncryptedSessionKeyPacket {
    if (buf.length < 2) {
      throw new PGPParseError('Buffer too small for SKESK packet');
    }

    const version = buf[0];
    const symmetricAlgorithm = buf[1] as SymmetricKeyAlgorithm;
    const { s2k, bytesRead } = parseS2K(buf, 2);
    const offset = 2 + bytesRead;
    const encryptedSessionKey = offset < buf.length ? buf.slice(offset) : undefined;

    return new SymEncryptedSessionKeyPacket({
      version,
      symmetricAlgorithm,
      s2k,
      encryptedSessionKey
    });
  }

  write(): Uint8Array {
    const s2kBytes = this.s2k.serialize();
    const parts: Uint8Array[] = [
      new Uint8Array([this.version, this.symmetricAlgorithm]),
      s2kBytes
    ];
    if (this.encryptedSessionKey) {
      parts.push(this.encryptedSessionKey);
    }
    return concatBytes(...parts);
  }
}
