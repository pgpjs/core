import { Packet } from './packet.js';
import { PacketTag } from '../types/enums.js';
import { concatBytes } from '../utils/bytes.js';

export class PacketList {
  packets: Packet[];

  constructor(packets: Packet[] = []) {
    this.packets = packets;
  }

  get length(): number {
    return this.packets.length;
  }

  push(...items: Packet[]): number {
    return this.packets.push(...items);
  }

  filterByTag<T extends Packet = Packet>(tag: PacketTag): T[] {
    return this.packets.filter((p) => p.tag === tag) as T[];
  }

  find<T extends Packet = Packet>(predicate: (packet: Packet) => boolean): T | undefined {
    return this.packets.find(predicate) as T | undefined;
  }

  filter(predicate: (packet: Packet) => boolean): PacketList {
    return new PacketList(this.packets.filter(predicate));
  }

  some(predicate: (packet: Packet) => boolean): boolean {
    return this.packets.some(predicate);
  }

  map<U>(fn: (packet: Packet, index: number) => U): U[] {
    return this.packets.map(fn);
  }

  forEach(fn: (packet: Packet, index: number) => void): void {
    this.packets.forEach(fn);
  }

  [Symbol.iterator](): Iterator<Packet> {
    return this.packets[Symbol.iterator]();
  }

  /**
   * Serializes all packets in sequence into a binary Uint8Array.
   */
  write(): Uint8Array {
    const serializedPackets = this.packets.map((p) => p.serialize());
    return concatBytes(...serializedPackets);
  }
}
