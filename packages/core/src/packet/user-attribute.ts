import { Packet } from './packet.js';
import { PacketTag } from '../types/enums.js';

export class UserAttributePacket extends Packet {
  tag = PacketTag.UserAttribute;
  data: Uint8Array;

  constructor(data: Uint8Array) {
    super();
    this.data = data;
  }

  static parse(data: Uint8Array): UserAttributePacket {
    return new UserAttributePacket(data);
  }

  write(): Uint8Array {
    return this.data;
  }
}
