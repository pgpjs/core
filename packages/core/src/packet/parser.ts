import { Packet } from './packet.js';
import { PacketList } from './packet-list.js';
import { PacketTag } from '../types/enums.js';
import { parsePacketHeader } from './header.js';
import { PublicKeyEncryptedSessionKeyPacket } from './pkesk.js';
import { SignaturePacket } from './signature.js';
import { SymEncryptedSessionKeyPacket } from './skesk.js';
import { OnePassSignaturePacket } from './one-pass-signature.js';
import { SecretKeyPacket, SecretSubkeyPacket } from './secret-key.js';
import { PublicKeyPacket, PublicSubkeyPacket } from './public-key.js';
import { CompressedDataPacket } from './compressed-data.js';
import { SymEncryptedDataPacket } from './sym-encrypted-data.js';
import { MarkerPacket } from './marker.js';
import { LiteralDataPacket } from './literal-data.js';
import { TrustPacket } from './trust.js';
import { UserIDPacket } from './user-id.js';
import { UserAttributePacket } from './user-attribute.js';
import { SymEncryptedIntegrityProtectedDataPacket } from './sym-encrypted-integrity-protected-data.js';
import { ModificationDetectionCodePacket } from './modification-detection-code.js';

/**
 * Parses raw binary OpenPGP data into a PacketList.
 */
export function parsePackets(buf: Uint8Array): PacketList {
  const packets: Packet[] = [];
  let offset = 0;

  while (offset < buf.length) {
    const header = parsePacketHeader(buf, offset);
    const bodyEnd = header.bodyOffset + header.bodyLength;
    if (bodyEnd > buf.length) {
      throw new Error(`Packet length exceeds buffer: expected ${bodyEnd}, available ${buf.length}`);
    }
    const body = buf.subarray(header.bodyOffset, bodyEnd);
    offset = header.bodyOffset + header.bodyLength;

    let packet: Packet;
    switch (header.tag) {
      case PacketTag.PublicKeyEncryptedSessionKey:
        packet = PublicKeyEncryptedSessionKeyPacket.parse(body);
        break;
      case PacketTag.Signature:
        packet = SignaturePacket.parse(body);
        break;
      case PacketTag.SymEncryptedSessionKey:
        packet = SymEncryptedSessionKeyPacket.parse(body);
        break;
      case PacketTag.OnePassSignature:
        packet = OnePassSignaturePacket.parse(body);
        break;
      case PacketTag.SecretKey:
        packet = SecretKeyPacket.parse(body, PacketTag.SecretKey);
        break;
      case PacketTag.PublicKey:
        packet = PublicKeyPacket.parse(body, PacketTag.PublicKey);
        break;
      case PacketTag.SecretSubkey:
        packet = SecretSubkeyPacket.parse(body);
        break;
      case PacketTag.CompressedData:
        packet = CompressedDataPacket.parse(body);
        break;
      case PacketTag.SymEncryptedData:
        packet = SymEncryptedDataPacket.parse(body);
        break;
      case PacketTag.Marker:
        packet = MarkerPacket.parse();
        break;
      case PacketTag.LiteralData:
        packet = LiteralDataPacket.parse(body);
        break;
      case PacketTag.Trust:
        packet = TrustPacket.parse(body);
        break;
      case PacketTag.UserID:
        packet = UserIDPacket.parse(body);
        break;
      case PacketTag.PublicSubkey:
        packet = PublicSubkeyPacket.parse(body);
        break;
      case PacketTag.UserAttribute:
        packet = UserAttributePacket.parse(body);
        break;
      case PacketTag.SymEncryptedIntegrityProtectedData:
        packet = SymEncryptedIntegrityProtectedDataPacket.parse(body);
        break;
      case PacketTag.ModificationDetectionCode:
        packet = ModificationDetectionCodePacket.parse(body);
        break;
      default:
        // Unknown or unhandled packet tag
        continue;
    }

    packets.push(packet);
  }

  return new PacketList(packets);
}
