import { Packet } from './packet.js';
import { PacketTag } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { concatBytes } from '../utils/bytes.js';

export class SymEncryptedIntegrityProtectedDataPacket extends Packet {
  tag = PacketTag.SymEncryptedIntegrityProtectedData;
  version: number = 1;
  encryptedData: Uint8Array;

  constructor(options: { version?: number; encryptedData: Uint8Array }) {
    super();
    this.version = options.version ?? 1;
    this.encryptedData = options.encryptedData;
  }

  static parse(buf: Uint8Array): SymEncryptedIntegrityProtectedDataPacket {
    if (buf.length < 1) {
      throw new PGPParseError('Buffer too small for SEIPD packet');
    }
    const version = buf[0];
    const encryptedData = buf.subarray(1);
    return new SymEncryptedIntegrityProtectedDataPacket({ version, encryptedData });
  }

  write(): Uint8Array {
    return concatBytes(new Uint8Array([this.version]), this.encryptedData);
  }
}
