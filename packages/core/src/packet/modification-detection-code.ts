import { Packet } from './packet.js';
import { PacketTag } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';

export class ModificationDetectionCodePacket extends Packet {
  tag = PacketTag.ModificationDetectionCode;
  digest: Uint8Array; // 20-byte SHA-1 digest

  constructor(digest: Uint8Array) {
    super();
    if (digest.length !== 20) {
      throw new PGPParseError(`MDC packet requires 20-byte SHA-1 digest, got ${digest.length}`);
    }
    this.digest = digest;
  }

  static parse(buf: Uint8Array): ModificationDetectionCodePacket {
    return new ModificationDetectionCodePacket(buf);
  }

  write(): Uint8Array {
    return this.digest;
  }
}
