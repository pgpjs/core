import { Packet } from './packet.js';
import { PacketTag } from '../types/enums.js';

export class SymEncryptedDataPacket extends Packet {
  tag = PacketTag.SymEncryptedData;
  encryptedData: Uint8Array;

  constructor(encryptedData: Uint8Array) {
    super();
    this.encryptedData = encryptedData;
  }

  static parse(buf: Uint8Array): SymEncryptedDataPacket {
    return new SymEncryptedDataPacket(buf);
  }

  write(): Uint8Array {
    return this.encryptedData;
  }
}
