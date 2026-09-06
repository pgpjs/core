import { Packet } from './packet.js';
import { PacketTag } from '../types/enums.js';

export class MarkerPacket extends Packet {
  tag = PacketTag.Marker;

  write(): Uint8Array {
    // RFC 4880 §5.8: literal bytes "PGP" (0x50 0x47 0x50)
    return new Uint8Array([0x50, 0x47, 0x50]);
  }

  static parse(): MarkerPacket {
    return new MarkerPacket();
  }
}
