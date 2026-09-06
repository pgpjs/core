import { Packet } from './packet.js';
import { PacketTag } from '../types/enums.js';
import { utf8ToBytes, bytesToUtf8 } from '../utils/bytes.js';

export class UserIDPacket extends Packet {
  tag = PacketTag.UserID;
  userId: string;

  constructor(userId: string) {
    super();
    this.userId = userId;
  }

  static parse(data: Uint8Array): UserIDPacket {
    return new UserIDPacket(bytesToUtf8(data));
  }

  write(): Uint8Array {
    return utf8ToBytes(this.userId);
  }
}
