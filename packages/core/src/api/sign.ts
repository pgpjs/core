import { ArmorType, HashAlgorithm, SignatureType } from '../types/enums.js';
import { SignOptions } from '../types/interfaces.js';
import { PGPSignatureError } from '../errors/index.js';
import { Message } from '../message/message.js';
import { CleartextMessage } from '../message/cleartext-message.js';
import { Key } from '../key/key.js';
import { SecretKeyPacket, SecretSubkeyPacket } from '../packet/secret-key.js';
import { OnePassSignaturePacket } from '../packet/one-pass-signature.js';
import { LiteralDataPacket } from '../packet/literal-data.js';
import { PacketList } from '../packet/packet-list.js';
import { armor } from '../armor/armor.js';
import { canonicalizeCleartext, formatCleartextSignedMessage } from '../armor/cleartext.js';
import { utf8ToBytes } from '../utils/bytes.js';
import { signPacket } from '../key/key-signing.js';

export async function sign(options: SignOptions): Promise<string | Uint8Array> {
  const signingKeys: Key[] = Array.isArray(options.signingKeys)
    ? options.signingKeys
    : [options.signingKeys];

  if (signingKeys.length === 0) {
    throw new PGPSignatureError('At least one signingKey is required to sign');
  }

  const primaryKey = signingKeys[0];
  const signingKeyPacket = await primaryKey.getSigningKey();
  if (
    !signingKeyPacket ||
    !(signingKeyPacket instanceof SecretKeyPacket || signingKeyPacket instanceof SecretSubkeyPacket)
  ) {
    throw new PGPSignatureError('Signing key must be an unlocked secret key');
  }

  const hashAlgorithm = options.hashAlgorithm ?? HashAlgorithm.SHA256;
  const detached = options.detached ?? false;
  const format = options.format ?? 'armored';

  // Handle CleartextMessage signing
  if (options.message instanceof CleartextMessage || (typeof options.message === 'string' && !detached && format === 'armored')) {
    const text = options.message instanceof CleartextMessage ? options.message.getText() : options.message;
    const canonicalText = canonicalizeCleartext(text);
    const dataToHash = utf8ToBytes(canonicalText);

    const sigPacket = signPacket(
      signingKeyPacket,
      SignatureType.CanonicalTextDocument,
      dataToHash,
      [],
      [],
      hashAlgorithm
    );

    const sigArmor = armor(ArmorType.Signature, sigPacket.serialize());
    return formatCleartextSignedMessage(text, sigArmor, hashAlgorithm);
  }

  // Handle binary or detached signing
  let payloadBytes: Uint8Array;
  let filename = '';
  let date = new Date();

  if (options.message instanceof Message) {
    payloadBytes = options.message.getBytes();
    filename = options.message.getFilename();
    date = options.message.getDate();
  } else if (typeof options.message === 'string') {
    payloadBytes = utf8ToBytes(options.message);
  } else if (options.message instanceof Uint8Array) {
    payloadBytes = options.message;
  } else {
    throw new PGPSignatureError('Invalid message parameter provided to sign');
  }

  if (detached) {
    const sigPacket = signPacket(
      signingKeyPacket,
      SignatureType.BinaryDocument,
      payloadBytes,
      [],
      [],
      hashAlgorithm
    );

    const sigBinary = sigPacket.serialize();
    if (format === 'binary') {
      return sigBinary;
    }
    return armor(ArmorType.Signature, sigBinary);
  }

  // Attached signature: OnePassSignature -> LiteralData -> Signature
  const pubKey = signingKeyPacket.publicKey;
  const ops = new OnePassSignaturePacket({
    signatureType: SignatureType.BinaryDocument,
    hashAlgorithm,
    publicKeyAlgorithm: pubKey.algorithm,
    issuerKeyID: pubKey.getKeyID(),
    nested: false
  });

  const literal = new LiteralDataPacket({
    data: payloadBytes,
    format: 'b',
    filename,
    date
  });

  const sigPacket = signPacket(
    signingKeyPacket,
    SignatureType.BinaryDocument,
    payloadBytes,
    [],
    [],
    hashAlgorithm
  );

  const packetList = new PacketList([ops, literal, sigPacket]);
  const binaryResult = packetList.write();

  if (format === 'binary') {
    return binaryResult;
  }
  return armor(ArmorType.Message, binaryResult);
}
