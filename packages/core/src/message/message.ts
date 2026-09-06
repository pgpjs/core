import { ArmorType, PacketTag } from '../types/enums.js';
import { PacketList } from '../packet/packet-list.js';
import { LiteralDataPacket } from '../packet/literal-data.js';
import { parsePackets } from '../packet/parser.js';
import { armor, dearmor, isArmored } from '../armor/armor.js';
import { bytesToUtf8, utf8ToBytes } from '../utils/bytes.js';
import { PGPParseError } from '../errors/index.js';

export class Message {
  packets: PacketList;

  constructor(packets: PacketList = new PacketList()) {
    this.packets = packets;
  }

  static fromText(text: string, filename: string = '', date: Date = new Date()): Message {
    const literal = new LiteralDataPacket({
      data: utf8ToBytes(text),
      format: 'u',
      filename,
      date
    });
    return new Message(new PacketList([literal]));
  }

  static fromBinary(bytes: Uint8Array, filename: string = '', date: Date = new Date()): Message {
    const literal = new LiteralDataPacket({
      data: bytes,
      format: 'b',
      filename,
      date
    });
    return new Message(new PacketList([literal]));
  }

  static fromPackets(packets: PacketList): Message {
    return new Message(packets);
  }

  static async read(input: string | Uint8Array): Promise<Message> {
    if (typeof input === 'string') {
      if (isArmored(input)) {
        const dearmored = dearmor(input);
        return new Message(parsePackets(dearmored.data));
      }
      return Message.fromText(input);
    }
    return new Message(parsePackets(input));
  }

  getLiteralData(): LiteralDataPacket | undefined {
    return this.packets.find((p) => p.tag === PacketTag.LiteralData) as LiteralDataPacket | undefined;
  }

  getText(): string {
    const lit = this.getLiteralData();
    if (!lit) {
      throw new PGPParseError('Message does not contain a LiteralData packet');
    }
    return bytesToUtf8(lit.data);
  }

  getBytes(): Uint8Array {
    const lit = this.getLiteralData();
    if (lit) {
      return lit.data;
    }
    return this.toBinary();
  }

  getFilename(): string {
    return this.getLiteralData()?.filename ?? '';
  }

  getDate(): Date {
    return this.getLiteralData()?.date ?? new Date();
  }

  getPackets(): PacketList {
    return this.packets;
  }

  isEncrypted(): boolean {
    return this.packets.some(
      (p) =>
        p.tag === PacketTag.SymEncryptedIntegrityProtectedData ||
        p.tag === PacketTag.SymEncryptedData ||
        p.tag === PacketTag.PublicKeyEncryptedSessionKey ||
        p.tag === PacketTag.SymEncryptedSessionKey
    );
  }

  isSigned(): boolean {
    return this.packets.some((p) => p.tag === PacketTag.Signature || p.tag === PacketTag.OnePassSignature);
  }

  toBinary(): Uint8Array {
    return this.packets.write();
  }

  async armor(): Promise<string> {
    return armor(ArmorType.Message, this.toBinary());
  }
}
