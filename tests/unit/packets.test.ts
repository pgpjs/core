import { describe, it, expect } from 'vitest';
import {
  parsePackets,
  PacketList,
  LiteralDataPacket,
  UserIDPacket,
  CompressedDataPacket,
  PublicKeyPacket,
  SecretKeyPacket,
  PublicSubkeyPacket,
  SecretSubkeyPacket,
  SignaturePacket,
  SubpacketBuilder,
  SymEncryptedIntegrityProtectedDataPacket,
  ModificationDetectionCodePacket,
  PublicKeyEncryptedSessionKeyPacket,
  SymEncryptedSessionKeyPacket
} from '../../packages/core/src/packet/index.js';
import {
  CompressionAlgorithm,
  HashAlgorithm,
  KeyFlag,
  PacketTag,
  PublicKeyAlgorithm,
  SignatureType,
  SymmetricKeyAlgorithm
} from '../../packages/core/src/types/enums.js';
import { utf8ToBytes, bytesToUtf8 } from '../../packages/core/src/utils/bytes.js';
import { generateECCKeyPair } from '../../packages/core/src/crypto/ecc.js';
import { S2K } from '../../packages/core/src/crypto/s2k.js';
import { getRandomBytes } from '../../packages/core/src/utils/random.js';

describe('Packet System', () => {
  it('serializes and parses LiteralDataPacket', () => {
    const originalText = 'Hello Literal Data!';
    const literal = new LiteralDataPacket({
      data: utf8ToBytes(originalText),
      format: 'u',
      filename: 'test.txt',
      date: new Date(1700000000000)
    });

    const serialized = literal.serialize();
    const parsedList = parsePackets(serialized);

    expect(parsedList.length).toBe(1);
    const parsed = parsedList.packets[0] as LiteralDataPacket;
    expect(parsed.tag).toBe(PacketTag.LiteralData);
    expect(parsed.format).toBe('u');
    expect(parsed.filename).toBe('test.txt');
    expect(bytesToUtf8(parsed.data)).toBe(originalText);
    expect(parsed.date.getTime()).toBe(1700000000000);
  });

  it('serializes and parses UserIDPacket', () => {
    const userStr = 'Alice <alice@example.com>';
    const user = new UserIDPacket(userStr);

    const serialized = user.serialize();
    const parsed = parsePackets(serialized).packets[0] as UserIDPacket;

    expect(parsed.tag).toBe(PacketTag.UserID);
    expect(parsed.userId).toBe(userStr);
  });

  it('serializes and parses CompressedDataPacket', () => {
    const data = utf8ToBytes('A'.repeat(500));
    const comp = CompressedDataPacket.fromPackets(data, CompressionAlgorithm.ZLIB);

    const serialized = comp.serialize();
    const parsed = parsePackets(serialized).packets[0] as CompressedDataPacket;

    expect(parsed.tag).toBe(PacketTag.CompressedData);
    expect(parsed.algorithm).toBe(CompressionAlgorithm.ZLIB);
    expect(bytesToUtf8(parsed.decompress())).toBe('A'.repeat(500));
  });

  it('serializes and parses PublicKeyPacket and computes fingerprint/keyID', () => {
    const ecc = generateECCKeyPair('ed25519');
    const pub = new PublicKeyPacket({
      algorithm: PublicKeyAlgorithm.EdDSA,
      curve: 'ed25519',
      publicKey: ecc.publicKey,
      creationTime: new Date(1700000000000)
    });

    const serialized = pub.serialize();
    const parsed = parsePackets(serialized).packets[0] as PublicKeyPacket;

    expect(parsed.tag).toBe(PacketTag.PublicKey);
    expect(parsed.algorithm).toBe(PublicKeyAlgorithm.EdDSA);
    expect(parsed.curve).toBe('ed25519');
    expect(parsed.publicKey).toEqual(ecc.publicKey);

    const fp = parsed.getFingerprintHex();
    expect(fp.length).toBe(40);
    const keyId = parsed.getKeyID();
    expect(keyId.length).toBe(16);
    expect(fp.endsWith(keyId)).toBe(true);
  });

  it('encrypts, decrypts, serializes and parses SecretKeyPacket', () => {
    const ecc = generateECCKeyPair('ed25519');
    const pub = new PublicKeyPacket({
      algorithm: PublicKeyAlgorithm.EdDSA,
      curve: 'ed25519',
      publicKey: ecc.publicKey,
      creationTime: new Date(1700000000000)
    });

    const sec = new SecretKeyPacket({
      publicKey: pub,
      privateKey: ecc.privateKey
    });

    expect(sec.isDecrypted).toBe(true);

    // Encrypt with passphrase
    sec.encrypt('secret-passphrase');
    expect(sec.isDecrypted).toBe(false);

    // Roundtrip serialized bytes
    const serialized = sec.serialize();
    const parsed = parsePackets(serialized).packets[0] as SecretKeyPacket;
    expect(parsed.isDecrypted).toBe(false);

    // Wrong password fails
    expect(() => parsed.decrypt('wrong-passphrase')).toThrow();

    // Correct password succeeds
    parsed.decrypt('secret-passphrase');
    expect(parsed.isDecrypted).toBe(true);
    expect(parsed.privateKey).toEqual(ecc.privateKey);
  });

  it('serializes and parses SignaturePacket with subpackets', () => {
    const sig = new SignaturePacket({
      signatureType: SignatureType.CanonicalTextDocument,
      publicKeyAlgorithm: PublicKeyAlgorithm.EdDSA,
      hashAlgorithm: HashAlgorithm.SHA256,
      hashedSubpackets: [
        SubpacketBuilder.signatureCreationTime(new Date(1700000000000)),
        SubpacketBuilder.keyFlags(KeyFlag.SignData, KeyFlag.Certify),
        SubpacketBuilder.issuerKeyID('1234567890ABCDEF')
      ],
      hashPrefix: new Uint8Array([0x12, 0x34]),
      signatureData: [new Uint8Array(32).fill(0xaa), new Uint8Array(32).fill(0xbb)]
    });

    const serialized = sig.serialize();
    const parsed = parsePackets(serialized).packets[0] as SignaturePacket;

    expect(parsed.signatureType).toBe(SignatureType.CanonicalTextDocument);
    expect(parsed.getCreationTime()?.getTime()).toBe(1700000000000);
    expect(parsed.getIssuerKeyID()).toBe('1234567890ABCDEF');
    expect(parsed.getKeyFlags()).toContain(KeyFlag.SignData);
    expect(parsed.signatureData.length).toBe(2);
  });

  it('handles multi-packet streams in PacketList', () => {
    const packets = new PacketList([
      new UserIDPacket('Alice <alice@example.com>'),
      new LiteralDataPacket({ data: utf8ToBytes('Content') })
    ]);

    const bytes = packets.write();
    const parsed = parsePackets(bytes);

    expect(parsed.length).toBe(2);
    expect(parsed.packets[0].tag).toBe(PacketTag.UserID);
    expect(parsed.packets[1].tag).toBe(PacketTag.LiteralData);
  });
});
