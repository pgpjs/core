import { ArmorType, PacketTag } from '../types/enums.js';
import { SignaturePacket } from '../packet/signature.js';
import { parsePackets } from '../packet/parser.js';
import { armor, dearmor, isArmored } from '../armor/armor.js';
import { PGPSignatureError } from '../errors/index.js';

export class Signature {
  packet: SignaturePacket;

  constructor(packet: SignaturePacket) {
    this.packet = packet;
  }

  static fromBinary(bytes: Uint8Array): Signature {
    const packets = parsePackets(bytes);
    const sigPacket = packets.find((p) => p.tag === PacketTag.Signature);
    if (!sigPacket) {
      throw new PGPSignatureError('No signature packet found in data');
    }
    return new Signature(sigPacket as SignaturePacket);
  }

  static fromArmored(armoredText: string): Signature {
    const dearmored = dearmor(armoredText);
    return Signature.fromBinary(dearmored.data);
  }

  static async read(input: string | Uint8Array): Promise<Signature> {
    if (typeof input === 'string' || (input instanceof Uint8Array && isArmored(input))) {
      const text = typeof input === 'string' ? input : new TextDecoder().decode(input);
      return Signature.fromArmored(text);
    }
    return Signature.fromBinary(input);
  }

  toBinary(): Uint8Array {
    return this.packet.serialize();
  }

  async armor(): Promise<string> {
    return armor(ArmorType.Signature, this.toBinary());
  }
}
