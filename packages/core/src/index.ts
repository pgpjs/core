// Public High-Level APIs
export {
  generateKeyPair,
  readKey,
  readKeys,
  readPrivateKey,
  readPublicKey,
  encryptKey,
  decryptKey,
  revokeKey,
  type KeyPairResult
} from './key/index.js';

export {
  createMessage,
  readMessage,
  createCleartextMessage,
  readCleartextMessage,
  encrypt,
  decrypt,
  sign,
  verify
} from './api/index.js';

export {
  armor,
  dearmor,
  isArmored,
  calculateCRC24,
  formatCRC24,
  parseCRC24,
  canonicalizeCleartext,
  formatCleartextSignedMessage,
  parseCleartextSignedMessage
} from './armor/index.js';

// Message & Key Objects
export { Key, Subkey } from './key/index.js';
export { Message, CleartextMessage, Signature } from './message/index.js';

// Packet System
export {
  Packet,
  PacketList,
  PublicKeyPacket,
  PublicSubkeyPacket,
  SecretKeyPacket,
  SecretSubkeyPacket,
  SignaturePacket,
  UserIDPacket,
  UserAttributePacket,
  LiteralDataPacket,
  CompressedDataPacket,
  SymEncryptedDataPacket,
  SymEncryptedIntegrityProtectedDataPacket,
  ModificationDetectionCodePacket,
  PublicKeyEncryptedSessionKeyPacket,
  SymEncryptedSessionKeyPacket,
  OnePassSignaturePacket,
  TrustPacket,
  MarkerPacket,
  parsePackets,
  parsePacketHeader,
  serializePacketHeader,
  wrapPacket,
  SubpacketBuilder
} from './packet/index.js';

// Crypto Primitives & Utilities
export {
  hash,
  getHash,
  getHashName,
  getHashDigestLength,
  getHashAlgorithmByName,
  S2K,
  parseS2K,
  decodeS2KCount,
  encodeS2KCount,
  encryptCFB,
  decryptCFB,
  encryptRawCFB,
  decryptRawCFB,
  generateRSAKeyPair,
  encryptRSA,
  decryptRSA,
  signRSA,
  verifyRSA,
  generateECCKeyPair,
  signECC,
  verifyECC,
  encryptECDH,
  decryptECDH
} from './crypto/index.js';

export {
  concatBytes,
  bytesEqual,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  utf8ToBytes,
  bytesToUtf8,
  readUint16BE,
  writeUint16BE,
  readUint32BE,
  writeUint32BE,
  getRandomBytes,
  parseMPI,
  serializeMPI,
  mpiToBigInt
} from './utils/index.js';

// Compression
export { compress, decompress } from './compression/index.js';

// Streaming
export {
  createEncryptStream,
  createDecryptStream,
  createSignStream,
  createVerifyStream,
  asyncIterableToStream
} from './stream/index.js';

// Types & Enums
export * from './types/index.js';

// Errors Hierarchy
export * from './errors/index.js';

// Policy, Store, Discovery & Inspection
export * from './policy/index.js';
export * from './store/index.js';
export * from './discovery/index.js';
export * from './inspection/index.js';

// High-Level Developer API
export * from './highlevel/index.js';
export { default } from './highlevel/index.js';
