export enum PacketTag {
  PublicKeyEncryptedSessionKey = 1,
  Signature = 2,
  SymEncryptedSessionKey = 3,
  OnePassSignature = 4,
  SecretKey = 5,
  PublicKey = 6,
  SecretSubkey = 7,
  CompressedData = 8,
  SymEncryptedData = 9,
  Marker = 10,
  LiteralData = 11,
  Trust = 12,
  UserID = 13,
  PublicSubkey = 14,
  UserAttribute = 17,
  SymEncryptedIntegrityProtectedData = 18,
  ModificationDetectionCode = 19,
  AEADEncryptedData = 20
}

/**
 * RFC 9580 AEAD algorithms (Section 9.6)
 */
export enum AEADAlgorithm {
  EAX = 1,
  OCB = 2,
  GCM = 3
}

export enum PublicKeyAlgorithm {
  RSA = 1,
  RSAEncryptOnly = 2,
  RSASignOnly = 3,
  ElgamalEncryptOnly = 16,
  DSA = 17,
  ECDH = 18,
  ECDSA = 19,
  Elgamal = 20,
  EdDSA = 22,
  X25519 = 25,
  Ed25519 = 27
}

export enum SymmetricKeyAlgorithm {
  Plaintext = 0,
  IDEA = 1,
  TripleDES = 2,
  CAST5 = 3,
  Blowfish = 4,
  AES128 = 7,
  AES192 = 8,
  AES256 = 9,
  Twofish = 10,
  Camellia128 = 11,
  Camellia192 = 12,
  Camellia256 = 13
}

export enum HashAlgorithm {
  MD5 = 1,
  SHA1 = 2,
  RIPEMD160 = 3,
  SHA256 = 8,
  SHA384 = 9,
  SHA512 = 10,
  SHA224 = 11,
  SHA3_256 = 12,
  SHA3_512 = 14
}

export enum CompressionAlgorithm {
  Uncompressed = 0,
  ZIP = 1,
  ZLIB = 2,
  BZIP2 = 3
}

export enum SignatureType {
  BinaryDocument = 0x00,
  CanonicalTextDocument = 0x01,
  Standalone = 0x02,
  GenericCertification = 0x10,
  PersonaCertification = 0x11,
  CasualCertification = 0x12,
  PositiveCertification = 0x13,
  SubkeyBinding = 0x18,
  PrimaryKeyBinding = 0x19,
  DirectKey = 0x1f,
  KeyRevocation = 0x20,
  SubkeyRevocation = 0x28,
  CertificationRevocation = 0x30,
  Timestamp = 0x40,
  ThirdParty = 0x50
}

export enum SignatureSubpacketType {
  CreationTime = 2,
  ExpirationTime = 3,
  ExportableCertification = 4,
  TrustSignature = 5,
  RegularExpression = 6,
  Revocable = 7,
  KeyExpirationTime = 9,
  PreferredSymmetricAlgorithms = 11,
  RevocationKey = 12,
  IssuerKeyID = 16,
  NotationData = 20,
  PreferredHashAlgorithms = 21,
  PreferredCompressionAlgorithms = 22,
  KeyServerPreferences = 23,
  PreferredKeyServer = 24,
  PrimaryUserID = 25,
  PolicyURI = 26,
  KeyFlags = 27,
  SignersUserID = 28,
  RevocationReason = 29,
  Features = 30,
  SignatureTarget = 31,
  EmbeddedSignature = 32,
  IssuerFingerprint = 33
}

export enum KeyFlag {
  Certify = 0x01,
  SignData = 0x02,
  EncryptCommunications = 0x04,
  EncryptStorage = 0x08,
  SplitKey = 0x10,
  Authenticate = 0x20,
  SharedKey = 0x80
}

export enum S2KType {
  Simple = 0,
  Salted = 1,
  IteratedAndSalted = 3,
  Argon2 = 4
}

export enum ArmorType {
  Message = 'MESSAGE',
  PublicKey = 'PUBLIC KEY BLOCK',
  PrivateKey = 'PRIVATE KEY BLOCK',
  Signature = 'SIGNATURE',
  ArmoredFile = 'ARMORED FILE'
}

export enum RevocationReasonCode {
  NoReason = 0,
  KeySuperceded = 1,
  KeyCompromised = 2,
  KeyRetired = 3,
  UserIDInvalid = 32
}
