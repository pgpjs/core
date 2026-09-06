import { Packet } from './packet.js';
import { PacketTag } from '../types/enums.js';
import { PGPParseError } from '../errors/index.js';
import { concatBytes, utf8ToBytes, bytesToUtf8, readUint32BE, writeUint32BE } from '../utils/bytes.js';

export class LiteralDataPacket extends Packet {
  tag = PacketTag.LiteralData;
  format: 'b' | 't' | 'u';
  filename: string;
  date: Date;
  data: Uint8Array;

  constructor(options: {
    data: Uint8Array;
    format?: 'b' | 't' | 'u';
    filename?: string;
    date?: Date;
  }) {
    super();
    this.data = options.data;
    this.format = options.format ?? 'u';
    this.filename = options.filename ?? '';
    this.date = options.date ?? new Date();
  }

  static parse(buf: Uint8Array): LiteralDataPacket {
    if (buf.length < 6) {
      throw new PGPParseError('Buffer too small for LiteralData packet header');
    }

    const formatByte = buf[0];
    const format = String.fromCharCode(formatByte) as 'b' | 't' | 'u';

    const fnLen = buf[1];
    if (buf.length < 2 + fnLen + 4) {
      throw new PGPParseError('Buffer too small for LiteralData filename and date');
    }

    const filenameBytes = buf.subarray(2, 2 + fnLen);
    const filename = bytesToUtf8(filenameBytes);

    const timestamp = readUint32BE(buf, 2 + fnLen);
    const date = new Date(timestamp * 1000);

    const data = buf.subarray(2 + fnLen + 4);

    return new LiteralDataPacket({
      data,
      format,
      filename,
      date
    });
  }

  write(): Uint8Array {
    const fnBytes = utf8ToBytes(this.filename);
    const fnLen = fnBytes.length;
    const timestamp = Math.floor(this.date.getTime() / 1000);

    return concatBytes(
      new Uint8Array([this.format.charCodeAt(0), fnLen]),
      fnBytes,
      writeUint32BE(timestamp),
      this.data
    );
  }
}
