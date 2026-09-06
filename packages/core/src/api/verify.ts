import { PacketTag } from '../types/enums.js';
import { VerifiedSignature, VerifyOptions, VerifyResult } from '../types/interfaces.js';
import { PGPVerificationError } from '../errors/index.js';
import { Message } from '../message/message.js';
import { CleartextMessage } from '../message/cleartext-message.js';
import { Signature } from '../message/signature.js';
import { Key } from '../key/key.js';
import { parsePackets } from '../packet/parser.js';
import { dearmor, isArmored } from '../armor/armor.js';
import { parseCleartextSignedMessage, canonicalizeCleartext } from '../armor/cleartext.js';
import { SignaturePacket } from '../packet/signature.js';
import { LiteralDataPacket } from '../packet/literal-data.js';
import { CompressedDataPacket } from '../packet/compressed-data.js';
import { bytesToUtf8, utf8ToBytes } from '../utils/bytes.js';
import { verifySignaturePacket } from '../key/key-signing.js';
import { PublicKeyPacket } from '../packet/public-key.js';
import { SecretKeyPacket, SecretSubkeyPacket } from '../packet/secret-key.js';

export async function verify(options: VerifyOptions): Promise<VerifyResult> {
  const verificationKeys: Key[] = Array.isArray(options.verificationKeys)
    ? options.verificationKeys
    : [options.verificationKeys];

  if (verificationKeys.length === 0) {
    throw new PGPVerificationError('At least one verificationKey is required to verify');
  }

  // 1. Check for Cleartext Signed Message
  if (
    options.message instanceof CleartextMessage ||
    (typeof options.message === 'string' && options.message.includes('-----BEGIN PGP SIGNED MESSAGE-----'))
  ) {
    const raw = options.message instanceof CleartextMessage ? await options.message.armor() : options.message;
    const parsed = parseCleartextSignedMessage(raw);
    const sigDearmored = dearmor(parsed.signatureArmor);
    const sigPackets = parsePackets(sigDearmored.data).filterByTag<SignaturePacket>(PacketTag.Signature);

    if (sigPackets.length === 0) {
      throw new PGPVerificationError('No signature packet found in cleartext signature block');
    }

    const sig = sigPackets[0];
    const canonicalText = canonicalizeCleartext(parsed.text);
    const dataToVerify = utf8ToBytes(canonicalText);

    const verifiedSig = verifySingleSignature(sig, dataToVerify, verificationKeys);

    return {
      data: utf8ToBytes(parsed.text),
      text: parsed.text,
      signatures: [verifiedSig]
    };
  }

  // 2. Check for Detached Signature
  if (options.signature) {
    let sigBinary: Uint8Array;
    if (options.signature instanceof Signature) {
      sigBinary = options.signature.toBinary();
    } else if (typeof options.signature === 'string') {
      sigBinary = dearmor(options.signature).data;
    } else if (isArmored(options.signature)) {
      sigBinary = dearmor(new TextDecoder().decode(options.signature)).data;
    } else {
      sigBinary = options.signature;
    }

    const sigPackets = parsePackets(sigBinary).filterByTag<SignaturePacket>(PacketTag.Signature);
    if (sigPackets.length === 0) {
      throw new PGPVerificationError('No signature packet found in detached signature');
    }

    let messageBytes: Uint8Array;
    if (options.message instanceof Message) {
      messageBytes = options.message.getBytes();
    } else if (typeof options.message === 'string') {
      messageBytes = utf8ToBytes(options.message);
    } else {
      messageBytes = options.message;
    }

    const signatures = sigPackets.map((sig) =>
      verifySingleSignature(sig, messageBytes, verificationKeys)
    );

    return {
      data: messageBytes,
      text: typeof options.message === 'string' ? options.message : undefined,
      signatures
    };
  }

  // 3. Attached Signature in Message
  let binary: Uint8Array;
  if (options.message instanceof Message) {
    binary = options.message.toBinary();
  } else if (typeof options.message === 'string') {
    binary = dearmor(options.message).data;
  } else if (isArmored(options.message)) {
    binary = dearmor(new TextDecoder().decode(options.message)).data;
  } else {
    binary = options.message;
  }

  let packets = parsePackets(binary);
  const comp = packets.find<CompressedDataPacket>((p) => p.tag === PacketTag.CompressedData);
  if (comp) {
    packets = parsePackets(comp.decompress());
  }

  const literal = packets.find<LiteralDataPacket>((p) => p.tag === PacketTag.LiteralData);
  if (!literal) {
    throw new PGPVerificationError('Message does not contain LiteralData packet for attached signature verification');
  }

  const sigPackets = packets.filterByTag<SignaturePacket>(PacketTag.Signature);
  const signatures = sigPackets.map((sig) =>
    verifySingleSignature(sig, literal.data, verificationKeys)
  );

  return {
    data: literal.data,
    text: (literal.format === 't' || literal.format === 'u') ? bytesToUtf8(literal.data) : undefined,
    signatures
  };
}

function verifySingleSignature(
  sig: SignaturePacket,
  dataToVerify: Uint8Array,
  keys: Key[]
): VerifiedSignature {
  const keyID = sig.getIssuerKeyID() ?? '';
  let valid = false;
  let matchingKey: PublicKeyPacket | undefined;

  for (const key of keys) {
    const candidates: PublicKeyPacket[] = [];
    if (key.primaryKey instanceof SecretKeyPacket) {
      candidates.push(key.primaryKey.publicKey);
    } else {
      candidates.push(key.primaryKey);
    }

    for (const sub of key.getSubkeys()) {
      if (sub.keyPacket instanceof SecretSubkeyPacket) {
        candidates.push(sub.keyPacket.publicKey);
      } else {
        candidates.push(sub.keyPacket);
      }
    }

    for (const cand of candidates) {
      if (!keyID || cand.getKeyID() === keyID) {
        matchingKey = cand;
        break;
      }
    }
    if (matchingKey) break;
  }

  if (matchingKey) {
    valid = verifySignaturePacket(matchingKey, sig, dataToVerify);
  }

  return {
    keyID,
    valid,
    verified: Promise.resolve(valid),
    signature: sig
  };
}
