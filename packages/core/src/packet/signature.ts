import { Packet } from './packet.js';
import {
  HashAlgorithm,
  KeyFlag,
  PacketTag,
  PublicKeyAlgorithm,
  RevocationReasonCode,
  SignatureSubpacketType,
  SignatureType
} from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import {
  concatBytes,
  bytesToHex,
  hexToBytes,
  readUint16BE,
  readUint32BE,
  writeUint16BE,
  writeUint32BE,
  bytesToUtf8,
  utf8ToBytes
} from '../utils/bytes.js';
import { parseMPI, serializeMPI } from '../utils/mpi.js';

export interface SignatureSubpacket {
  type: SignatureSubpacketType;
  critical?: boolean;
  data: Uint8Array;
}

export class SignaturePacket extends Packet {
  tag: PacketTag = PacketTag.Signature;
  version: number = 4;
  signatureType: SignatureType;
  publicKeyAlgorithm: PublicKeyAlgorithm;
  hashAlgorithm: HashAlgorithm;

  hashedSubpackets: SignatureSubpacket[];
  unhashedSubpackets: SignatureSubpacket[];
  hashPrefix: Uint8Array; // 2 octets
  signatureData: Uint8Array[]; // MPIs

  constructor(options: {
    version?: number;
    signatureType: SignatureType;
    publicKeyAlgorithm: PublicKeyAlgorithm;
    hashAlgorithm: HashAlgorithm;
    hashedSubpackets?: SignatureSubpacket[];
    unhashedSubpackets?: SignatureSubpacket[];
    hashPrefix?: Uint8Array;
    signatureData?: Uint8Array[];
  }) {
    super();
    this.version = options.version ?? 4;
    this.signatureType = options.signatureType;
    this.publicKeyAlgorithm = options.publicKeyAlgorithm;
    this.hashAlgorithm = options.hashAlgorithm;
    this.hashedSubpackets = options.hashedSubpackets ?? [];
    this.unhashedSubpackets = options.unhashedSubpackets ?? [];
    this.hashPrefix = options.hashPrefix ?? new Uint8Array(2);
    this.signatureData = options.signatureData ?? [];
  }

  static parse(buf: Uint8Array): SignaturePacket {
    if (buf.length < 5) {
      throw new PGPParseError('Buffer too small for signature packet header');
    }

    const version = buf[0];
    if (version !== 4) {
      throw new PGPParseError(`Unsupported signature version: ${version}`);
    }

    const signatureType = buf[1] as SignatureType;
    const publicKeyAlgorithm = buf[2] as PublicKeyAlgorithm;
    const hashAlgorithm = buf[3] as HashAlgorithm;

    let offset = 4;
    if (buf.length < offset + 2) {
      throw new PGPParseError('Buffer too small for hashed subpackets length');
    }

    const hashedLen = readUint16BE(buf, offset);
    offset += 2;

    if (buf.length < offset + hashedLen + 2) {
      throw new PGPParseError('Buffer too small for hashed subpackets');
    }

    const hashedData = buf.subarray(offset, offset + hashedLen);
    offset += hashedLen;
    const hashedSubpackets = parseSubpackets(hashedData);

    const unhashedLen = readUint16BE(buf, offset);
    offset += 2;

    if (buf.length < offset + unhashedLen + 2) {
      throw new PGPParseError('Buffer too small for unhashed subpackets');
    }

    const unhashedData = buf.subarray(offset, offset + unhashedLen);
    offset += unhashedLen;
    const unhashedSubpackets = parseSubpackets(unhashedData);

    const hashPrefix = buf.slice(offset, offset + 2);
    offset += 2;

    const signatureData: Uint8Array[] = [];
    while (offset < buf.length) {
      const mpi = parseMPI(buf, offset);
      signatureData.push(mpi.data);
      offset += mpi.byteLength;
    }

    return new SignaturePacket({
      version,
      signatureType,
      publicKeyAlgorithm,
      hashAlgorithm,
      hashedSubpackets,
      unhashedSubpackets,
      hashPrefix,
      signatureData
    });
  }

  /**
   * Serializes the hashed subpackets data block (prefixed with 2-byte length).
   */
  getHashedSubpacketBytes(): Uint8Array {
    const raw = serializeSubpackets(this.hashedSubpackets);
    return concatBytes(writeUint16BE(raw.length), raw);
  }

  /**
   * Serializes the signature trailer data hashed in v4 signatures:
   * 0x04 || signatureType || publicKeyAlgorithm || hashAlgorithm || 2-octet hashed subpacket length || hashed subpacket data
   */
  getSignatureTrailer(): Uint8Array {
    const hashedSubpacketBytes = this.getHashedSubpacketBytes();
    return concatBytes(
      new Uint8Array([this.version, this.signatureType, this.publicKeyAlgorithm, this.hashAlgorithm]),
      hashedSubpacketBytes
    );
  }

  write(): Uint8Array {
    const trailer = this.getSignatureTrailer();
    const unhashedRaw = serializeSubpackets(this.unhashedSubpackets);
    const unhashedPart = concatBytes(writeUint16BE(unhashedRaw.length), unhashedRaw);

    const mpiParts: Uint8Array[] = [];
    for (const mpiData of this.signatureData) {
      mpiParts.push(serializeMPI(mpiData));
    }

    return concatBytes(trailer, unhashedPart, this.hashPrefix, ...mpiParts);
  }

  // --- Subpacket query helpers ---

  findSubpacket(type: SignatureSubpacketType): SignatureSubpacket | undefined {
    return (
      this.hashedSubpackets.find((s) => s.type === type) ??
      this.unhashedSubpackets.find((s) => s.type === type)
    );
  }

  getCreationTime(): Date | null {
    const sp = this.findSubpacket(SignatureSubpacketType.CreationTime);
    if (!sp || sp.data.length < 4) return null;
    return new Date(readUint32BE(sp.data, 0) * 1000);
  }

  getExpirationTime(): Date | null {
    const sp = this.findSubpacket(SignatureSubpacketType.ExpirationTime);
    if (!sp || sp.data.length < 4) return null;
    const duration = readUint32BE(sp.data, 0);
    const creation = this.getCreationTime();
    if (!creation) return null;
    return new Date(creation.getTime() + duration * 1000);
  }

  getKeyExpirationTime(): Date | null {
    const sp = this.findSubpacket(SignatureSubpacketType.KeyExpirationTime);
    if (!sp || sp.data.length < 4) return null;
    const duration = readUint32BE(sp.data, 0);
    const creation = this.getCreationTime();
    if (!creation) return null;
    return new Date(creation.getTime() + duration * 1000);
  }

  getIssuerKeyID(): string | null {
    const sp = this.findSubpacket(SignatureSubpacketType.IssuerKeyID);
    if (!sp || sp.data.length < 8) return null;
    return bytesToHex(sp.data.subarray(0, 8)).toUpperCase();
  }

  getIssuerFingerprint(): string | null {
    const sp = this.findSubpacket(SignatureSubpacketType.IssuerFingerprint);
    if (!sp || sp.data.length < 21) return null;
    return bytesToHex(sp.data.subarray(1, 21)).toUpperCase();
  }

  getKeyFlags(): KeyFlag[] {
    const sp = this.findSubpacket(SignatureSubpacketType.KeyFlags);
    if (!sp || sp.data.length === 0) return [];
    const flags: KeyFlag[] = [];
    const byte = sp.data[0];
    for (const flag of [
      KeyFlag.Certify,
      KeyFlag.SignData,
      KeyFlag.EncryptCommunications,
      KeyFlag.EncryptStorage,
      KeyFlag.SplitKey,
      KeyFlag.Authenticate,
      KeyFlag.SharedKey
    ]) {
      if ((byte & flag) !== 0) {
        flags.push(flag);
      }
    }
    return flags;
  }

  getRevocationReason(): { code: RevocationReasonCode; description: string } | null {
    const sp = this.findSubpacket(SignatureSubpacketType.RevocationReason);
    if (!sp || sp.data.length < 1) return null;
    const code = sp.data[0] as RevocationReasonCode;
    const description = bytesToUtf8(sp.data.subarray(1));
    return { code, description };
  }

  isRevocation(): boolean {
    return (
      this.signatureType === SignatureType.KeyRevocation ||
      this.signatureType === SignatureType.SubkeyRevocation ||
      this.signatureType === SignatureType.CertificationRevocation
    );
  }
}

/**
 * Parses subpackets from raw bytes.
 */
export function parseSubpackets(buf: Uint8Array): SignatureSubpacket[] {
  const result: SignatureSubpacket[] = [];
  let offset = 0;

  while (offset < buf.length) {
    let len = buf[offset++];
    if (len >= 192 && len < 255) {
      len = ((len - 192) << 8) + buf[offset++] + 192;
    } else if (len === 255) {
      len = readUint32BE(buf, offset);
      offset += 4;
    }

    if (len === 0) continue;
    if (offset + len > buf.length) {
      break;
    }

    const typeByte = buf[offset];
    const critical = (typeByte & 0x80) !== 0;
    const type = (typeByte & 0x7f) as SignatureSubpacketType;
    const data = buf.slice(offset + 1, offset + len);
    offset += len;

    result.push({ type, critical, data });
  }

  return result;
}

/**
 * Serializes an array of subpackets into binary bytes.
 */
export function serializeSubpackets(subpackets: SignatureSubpacket[]): Uint8Array {
  const parts: Uint8Array[] = [];

  for (const sp of subpackets) {
    const bodyLen = 1 + sp.data.length;
    let lenBytes: Uint8Array;

    if (bodyLen < 192) {
      lenBytes = new Uint8Array([bodyLen]);
    } else if (bodyLen < 8384) {
      const adjusted = bodyLen - 192;
      lenBytes = new Uint8Array([((adjusted >> 8) & 0xff) + 192, adjusted & 0xff]);
    } else {
      lenBytes = new Uint8Array([
        255,
        (bodyLen >>> 24) & 0xff,
        (bodyLen >>> 16) & 0xff,
        (bodyLen >>> 8) & 0xff,
        bodyLen & 0xff
      ]);
    }

    const typeByte = (sp.critical ? 0x80 : 0x00) | (sp.type & 0x7f);
    parts.push(lenBytes, new Uint8Array([typeByte]), sp.data);
  }

  return concatBytes(...parts);
}

/**
 * Creates standard subpacket builders.
 */
export const SubpacketBuilder = {
  signatureCreationTime(date: Date = new Date()): SignatureSubpacket {
    const timestamp = Math.floor(date.getTime() / 1000);
    return {
      type: SignatureSubpacketType.CreationTime,
      critical: true,
      data: writeUint32BE(timestamp)
    };
  },

  signatureExpirationTime(durationSeconds: number): SignatureSubpacket {
    return {
      type: SignatureSubpacketType.ExpirationTime,
      critical: true,
      data: writeUint32BE(durationSeconds)
    };
  },

  keyExpirationTime(durationSeconds: number): SignatureSubpacket {
    return {
      type: SignatureSubpacketType.KeyExpirationTime,
      critical: true,
      data: writeUint32BE(durationSeconds)
    };
  },

  issuerKeyID(keyID: string): SignatureSubpacket {
    return {
      type: SignatureSubpacketType.IssuerKeyID,
      data: hexToBytes(keyID)
    };
  },

  issuerFingerprint(fingerprint: string): SignatureSubpacket {
    const fpBytes = hexToBytes(fingerprint);
    return {
      type: SignatureSubpacketType.IssuerFingerprint,
      data: concatBytes(new Uint8Array([4]), fpBytes)
    };
  },

  keyFlags(...flags: KeyFlag[]): SignatureSubpacket {
    let byte = 0;
    for (const flag of flags) {
      byte |= flag;
    }
    return {
      type: SignatureSubpacketType.KeyFlags,
      critical: true,
      data: new Uint8Array([byte])
    };
  },

  preferredSymmetricAlgorithms(...algos: number[]): SignatureSubpacket {
    return {
      type: SignatureSubpacketType.PreferredSymmetricAlgorithms,
      data: new Uint8Array(algos)
    };
  },

  preferredHashAlgorithms(...algos: number[]): SignatureSubpacket {
    return {
      type: SignatureSubpacketType.PreferredHashAlgorithms,
      data: new Uint8Array(algos)
    };
  },

  preferredCompressionAlgorithms(...algos: number[]): SignatureSubpacket {
    return {
      type: SignatureSubpacketType.PreferredCompressionAlgorithms,
      data: new Uint8Array(algos)
    };
  },

  primaryUserID(): SignatureSubpacket {
    return {
      type: SignatureSubpacketType.PrimaryUserID,
      data: new Uint8Array([1])
    };
  },

  revocationReason(code: RevocationReasonCode, reason: string): SignatureSubpacket {
    return {
      type: SignatureSubpacketType.RevocationReason,
      critical: true,
      data: concatBytes(new Uint8Array([code]), utf8ToBytes(reason))
    };
  }
};
