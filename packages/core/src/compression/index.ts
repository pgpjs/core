import { deflateSync, inflateSync, zlibSync, unzlibSync } from 'fflate';
import { CompressionAlgorithm } from '../types/enums.js';
import { PGPAlgorithmError } from '../errors/index.js';

export function compress(data: Uint8Array, algorithm: CompressionAlgorithm): Uint8Array {
  switch (algorithm) {
    case CompressionAlgorithm.Uncompressed:
      return data;
    case CompressionAlgorithm.ZIP:
      return deflateSync(data, { level: 6 });
    case CompressionAlgorithm.ZLIB:
      return zlibSync(data, { level: 6 });
    default:
      throw new PGPAlgorithmError(`Unsupported compression algorithm: ${algorithm}`);
  }
}

export function decompress(data: Uint8Array, algorithm: CompressionAlgorithm): Uint8Array {
  switch (algorithm) {
    case CompressionAlgorithm.Uncompressed:
      return data;
    case CompressionAlgorithm.ZIP:
      return inflateSync(data);
    case CompressionAlgorithm.ZLIB:
      return unzlibSync(data);
    default:
      throw new PGPAlgorithmError(`Unsupported compression algorithm: ${algorithm}`);
  }
}
