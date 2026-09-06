import { Packet } from './packet.js';
import { PacketTag, CompressionAlgorithm } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { concatBytes } from '../utils/bytes.js';
import { compress, decompress } from '../compression/index.js';

export class CompressedDataPacket extends Packet {
  tag = PacketTag.CompressedData;
  algorithm: CompressionAlgorithm;
  compressedData: Uint8Array;

  constructor(options: { algorithm: CompressionAlgorithm; compressedData: Uint8Array }) {
    super();
    this.algorithm = options.algorithm;
    this.compressedData = options.compressedData;
  }

  static fromPackets(packetsBytes: Uint8Array, algorithm: CompressionAlgorithm = CompressionAlgorithm.ZLIB): CompressedDataPacket {
    const compressedData = compress(packetsBytes, algorithm);
    return new CompressedDataPacket({ algorithm, compressedData });
  }

  static parse(buf: Uint8Array): CompressedDataPacket {
    if (buf.length < 1) {
      throw new PGPParseError('Buffer too small for CompressedData packet');
    }
    const algorithm = buf[0] as CompressionAlgorithm;
    const compressedData = buf.subarray(1);
    return new CompressedDataPacket({ algorithm, compressedData });
  }

  decompress(): Uint8Array {
    return decompress(this.compressedData, this.algorithm);
  }

  write(): Uint8Array {
    return concatBytes(new Uint8Array([this.algorithm]), this.compressedData);
  }
}
