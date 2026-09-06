import { Key } from './key.js';
import { isArmored, dearmor } from '../armor/armor.js';
import { parsePackets } from '../packet/parser.js';
import { PGPKeyError } from '../errors/index.js';
import { PacketTag } from '../types/enums.js';
import { PacketList } from '../packet/packet-list.js';

export interface ReadKeyOptions {
  armoredKey?: string;
  binaryKey?: Uint8Array;
}

export interface ReadKeysOptions {
  armoredKeys?: string;
  binaryKeys?: Uint8Array;
}

/**
 * Reads a single OpenPGP key from ASCII armor or binary bytes.
 */
export async function readKey(options: ReadKeyOptions): Promise<Key> {
  const keys = await readKeys({
    armoredKeys: options.armoredKey,
    binaryKeys: options.binaryKey
  });

  if (keys.length === 0) {
    throw new PGPKeyError('No key found in input');
  }
  return keys[0];
}

/**
 * Reads one or more OpenPGP keys from ASCII armor or binary bytes.
 */
export async function readKeys(options: ReadKeysOptions): Promise<Key[]> {
  let binary: Uint8Array;

  if (options.armoredKeys) {
    if (isArmored(options.armoredKeys)) {
      // Split multiple armored blocks if present
      const blocks = options.armoredKeys.match(/-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----[\s\S]*?-----END PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----/g);
      if (blocks && blocks.length > 1) {
        const result: Key[] = [];
        for (const block of blocks) {
          result.push(Key.fromArmored(block));
        }
        return result;
      }
      const dearmored = dearmor(options.armoredKeys);
      binary = dearmored.data;
    } else {
      throw new PGPKeyError('Input is not valid ASCII armored OpenPGP key text');
    }
  } else if (options.binaryKeys) {
    binary = options.binaryKeys;
  } else {
    throw new PGPKeyError('Neither armoredKeys nor binaryKeys was provided');
  }

  const allPackets = parsePackets(binary);
  const keys: Key[] = [];
  let currentKeyPackets = new PacketList();

  for (const packet of allPackets) {
    if (
      (packet.tag === PacketTag.PublicKey || packet.tag === PacketTag.SecretKey) &&
      currentKeyPackets.length > 0
    ) {
      keys.push(Key.fromPackets(currentKeyPackets));
      currentKeyPackets = new PacketList();
    }
    currentKeyPackets.push(packet);
  }

  if (currentKeyPackets.length > 0) {
    keys.push(Key.fromPackets(currentKeyPackets));
  }

  return keys;
}

export async function readPrivateKey(options: ReadKeyOptions): Promise<Key> {
  const key = await readKey(options);
  if (!key.isPrivate()) {
    throw new PGPKeyError('Expected private key, but parsed public key');
  }
  return key;
}

export async function readPublicKey(options: ReadKeyOptions): Promise<Key> {
  const key = await readKey(options);
  if (key.isPrivate()) {
    throw new PGPKeyError('Expected public key, but parsed private key');
  }
  return key;
}

export async function encryptKey(options: { key: Key; passphrase: string }): Promise<Key> {
  return options.key.encrypt(options.passphrase);
}

export async function decryptKey(options: { key: Key; passphrase: string }): Promise<Key> {
  return options.key.decrypt(options.passphrase);
}

export async function revokeKey(options: {
  key: Key;
  reason?: string;
  revocationCertificate?: string;
}): Promise<Key> {
  if (options.revocationCertificate) {
    // Apply revocation certificate
    const dearmored = dearmor(options.revocationCertificate);
    const packets = parsePackets(dearmored.data);
    const sigPacket = packets.find((p) => p.tag === PacketTag.Signature);
    if (!sigPacket) {
      throw new PGPKeyError('Invalid revocation certificate: missing signature packet');
    }
    options.key.revocations.push(sigPacket as any);
    return options.key;
  }
  const { key } = await options.key.revoke(options.reason);
  return key;
}
