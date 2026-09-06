import { PacketTag } from '../types/enums.js';
import { wrapPacket } from './header.js';

/**
 * Base class for all OpenPGP packets.
 */
export abstract class Packet {
  abstract tag: PacketTag;

  /**
   * Writes the packet body (without the packet header).
   */
  abstract write(): Uint8Array;

  /**
   * Serializes the packet into standard OpenPGP binary format (header + body).
   */
  serialize(): Uint8Array {
    return wrapPacket(this.tag, this.write());
  }
}
