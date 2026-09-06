import { Packet } from './packet.js';
import { PacketTag } from '../types/enums.js';

export class TrustPacket extends Packet {
  tag = PacketTag.Trust;
  data: Uint8Array;

  constructor(data: Uint8Array) {
    super();
    this.data = data;
  }

  write(): Uint8Array {
    return this.data;
  }

  static parse(data: Uint8Array): TrustPacket {
    return new TrustPacket(data);
  }
}
