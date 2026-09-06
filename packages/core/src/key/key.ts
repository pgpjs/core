import { ArmorType, KeyFlag, PacketTag, PublicKeyAlgorithm, RevocationReasonCode, SignatureType } from '../types/enums.js';
import { AlgorithmInfo } from '../types/interfaces.js';
import { PGPKeyError, PGPParseError } from '../errors/index.js';
import { PublicKeyPacket, PublicSubkeyPacket } from '../packet/public-key.js';
import { SecretKeyPacket, SecretSubkeyPacket } from '../packet/secret-key.js';
import { UserIDPacket } from '../packet/user-id.js';
import { UserAttributePacket } from '../packet/user-attribute.js';
import { SignaturePacket, SubpacketBuilder } from '../packet/signature.js';
import { PacketList } from '../packet/packet-list.js';
import { parsePackets } from '../packet/parser.js';
import { armor, dearmor, isArmored } from '../armor/armor.js';
import { Subkey } from './subkeys.js';
import { getKeyRevocationData, signPacket } from './key-signing.js';

export interface UserEntry {
  user: UserIDPacket;
  selfCertifications: SignaturePacket[];
  revocations: SignaturePacket[];
  userAttributes: UserAttributePacket[];
}

export class Key {
  primaryKey: PublicKeyPacket | SecretKeyPacket;
  users: UserEntry[] = [];
  subkeys: Subkey[] = [];
  directSignatures: SignaturePacket[] = [];
  revocations: SignaturePacket[] = [];

  constructor(options: {
    primaryKey: PublicKeyPacket | SecretKeyPacket;
    users?: UserEntry[];
    subkeys?: Subkey[];
    directSignatures?: SignaturePacket[];
    revocations?: SignaturePacket[];
  }) {
    this.primaryKey = options.primaryKey;
    this.users = options.users ?? [];
    this.subkeys = options.subkeys ?? [];
    this.directSignatures = options.directSignatures ?? [];
    this.revocations = options.revocations ?? [];
  }

  static fromPackets(packetList: PacketList): Key {
    if (packetList.length === 0) {
      throw new PGPParseError('Empty packet list: no key found');
    }

    const firstPacket = packetList.packets[0];
    if (
      firstPacket.tag !== PacketTag.PublicKey &&
      firstPacket.tag !== PacketTag.SecretKey
    ) {
      throw new PGPParseError(`Expected Public or Secret Key packet as first packet, got tag ${firstPacket.tag}`);
    }

    const primaryKey = firstPacket as PublicKeyPacket | SecretKeyPacket;
    const users: UserEntry[] = [];
    const subkeys: Subkey[] = [];
    const directSignatures: SignaturePacket[] = [];
    const revocations: SignaturePacket[] = [];

    let currentUserEntry: UserEntry | null = null;
    let currentSubkey: Subkey | null = null;

    for (let i = 1; i < packetList.length; i++) {
      const p = packetList.packets[i];

      if (p.tag === PacketTag.UserID) {
        currentUserEntry = {
          user: p as UserIDPacket,
          selfCertifications: [],
          revocations: [],
          userAttributes: []
        };
        users.push(currentUserEntry);
        currentSubkey = null;
      } else if (p.tag === PacketTag.UserAttribute) {
        if (currentUserEntry) {
          currentUserEntry.userAttributes.push(p as UserAttributePacket);
        }
      } else if (p.tag === PacketTag.PublicSubkey || p.tag === PacketTag.SecretSubkey) {
        currentSubkey = new Subkey(p as PublicSubkeyPacket | SecretSubkeyPacket);
        subkeys.push(currentSubkey);
        currentUserEntry = null;
      } else if (p.tag === PacketTag.Signature) {
        const sig = p as SignaturePacket;

        if (currentSubkey) {
          if (sig.signatureType === SignatureType.SubkeyRevocation) {
            currentSubkey.revocationSignatures.push(sig);
          } else if (sig.signatureType === SignatureType.SubkeyBinding) {
            currentSubkey.bindingSignature = sig;
          }
        } else if (currentUserEntry) {
          if (sig.signatureType === SignatureType.CertificationRevocation) {
            currentUserEntry.revocations.push(sig);
          } else if (
            sig.signatureType === SignatureType.GenericCertification ||
            sig.signatureType === SignatureType.PersonaCertification ||
            sig.signatureType === SignatureType.CasualCertification ||
            sig.signatureType === SignatureType.PositiveCertification
          ) {
            currentUserEntry.selfCertifications.push(sig);
          }
        } else {
          if (sig.signatureType === SignatureType.KeyRevocation) {
            revocations.push(sig);
          } else if (sig.signatureType === SignatureType.DirectKey) {
            directSignatures.push(sig);
          }
        }
      }
    }

    return new Key({
      primaryKey,
      users,
      subkeys,
      directSignatures,
      revocations
    });
  }

  static fromBinary(data: Uint8Array): Key {
    const packets = parsePackets(data);
    return Key.fromPackets(packets);
  }

  static fromArmored(armoredText: string): Key {
    const dearmored = dearmor(armoredText);
    return Key.fromBinary(dearmored.data);
  }

  isPrivate(): boolean {
    return this.primaryKey instanceof SecretKeyPacket;
  }

  get isDecrypted(): boolean {
    if (!this.isPrivate()) {
      return true;
    }
    return (this.primaryKey as SecretKeyPacket).isDecrypted;
  }

  isRevoked(): boolean {
    return this.revocations.length > 0;
  }

  getFingerprint(): string {
    if (this.primaryKey instanceof SecretKeyPacket) {
      return this.primaryKey.publicKey.getFingerprintHex();
    }
    return this.primaryKey.getFingerprintHex();
  }

  getKeyID(): string {
    if (this.primaryKey instanceof SecretKeyPacket) {
      return this.primaryKey.publicKey.getKeyID();
    }
    return this.primaryKey.getKeyID();
  }

  getCreationTime(): Date {
    if (this.primaryKey instanceof SecretKeyPacket) {
      return this.primaryKey.publicKey.creationTime;
    }
    return this.primaryKey.creationTime;
  }

  getExpirationTime(): Date | null {
    const primaryUser = this.getPrimaryUser();
    if (primaryUser?.selfCertification) {
      const exp = primaryUser.selfCertification.getKeyExpirationTime();
      if (exp) return exp;
    }
    for (const sig of this.directSignatures) {
      const exp = sig.getKeyExpirationTime();
      if (exp) return exp;
    }
    return null;
  }

  isExpired(): boolean {
    const exp = this.getExpirationTime();
    return exp !== null && exp.getTime() < Date.now();
  }

  getUserIDs(): string[] {
    return this.users.map((u) => u.user.userId);
  }

  getPrimaryUser(): { user: UserIDPacket; selfCertification?: SignaturePacket } | null {
    if (this.users.length === 0) return null;
    return {
      user: this.users[0].user,
      selfCertification: this.users[0].selfCertifications[0]
    };
  }

  getSubkeys(): Subkey[] {
    return this.subkeys;
  }

  getAlgorithmInfo(): AlgorithmInfo {
    const pk = this.primaryKey instanceof SecretKeyPacket ? this.primaryKey.publicKey : this.primaryKey;
    const algo = pk.algorithm;

    if (
      algo === PublicKeyAlgorithm.RSA ||
      algo === PublicKeyAlgorithm.RSAEncryptOnly ||
      algo === PublicKeyAlgorithm.RSASignOnly
    ) {
      const bits = pk.n ? pk.n.toString(2).length : undefined;
      return { algorithm: 'RSA', bits };
    } else if (
      algo === PublicKeyAlgorithm.EdDSA ||
      algo === PublicKeyAlgorithm.ECDSA ||
      algo === PublicKeyAlgorithm.ECDH
    ) {
      return { algorithm: PublicKeyAlgorithm[algo] ?? 'ECC', curve: pk.curve };
    }
    return { algorithm: 'Unknown' };
  }

  async getEncryptionKey(): Promise<PublicKeyPacket | SecretKeyPacket | null> {
    for (const subkey of this.subkeys) {
      if (!subkey.isRevoked() && subkey.canEncrypt()) {
        return subkey.keyPacket;
      }
    }
    const pk = this.primaryKey;
    const algo = pk instanceof SecretKeyPacket ? pk.publicKey.algorithm : pk.algorithm;
    if (algo === PublicKeyAlgorithm.RSA || algo === PublicKeyAlgorithm.RSAEncryptOnly) {
      return pk;
    }
    return null;
  }

  async getSigningKey(): Promise<PublicKeyPacket | SecretKeyPacket | null> {
    for (const subkey of this.subkeys) {
      if (!subkey.isRevoked() && subkey.canSign()) {
        return subkey.keyPacket;
      }
    }
    const pk = this.primaryKey;
    const algo = pk instanceof SecretKeyPacket ? pk.publicKey.algorithm : pk.algorithm;
    if (
      algo === PublicKeyAlgorithm.RSA ||
      algo === PublicKeyAlgorithm.RSASignOnly ||
      algo === PublicKeyAlgorithm.EdDSA ||
      algo === PublicKeyAlgorithm.ECDSA
    ) {
      return pk;
    }
    return null;
  }

  toPackets(): PacketList {
    const packets = new PacketList();
    packets.push(this.primaryKey);

    for (const rev of this.revocations) {
      packets.push(rev);
    }
    for (const direct of this.directSignatures) {
      packets.push(direct);
    }

    for (const user of this.users) {
      packets.push(user.user);
      for (const attr of user.userAttributes) {
        packets.push(attr);
      }
      for (const cert of user.selfCertifications) {
        packets.push(cert);
      }
      for (const rev of user.revocations) {
        packets.push(rev);
      }
    }

    for (const subkey of this.subkeys) {
      packets.push(subkey.keyPacket);
      if (subkey.bindingSignature) {
        packets.push(subkey.bindingSignature);
      }
      for (const rev of subkey.revocationSignatures) {
        packets.push(rev);
      }
    }

    return packets;
  }

  toBinary(): Uint8Array {
    return this.toPackets().write();
  }

  async armor(): Promise<string> {
    const type = this.isPrivate() ? ArmorType.PrivateKey : ArmorType.PublicKey;
    return armor(type, this.toBinary());
  }

  toPublic(): Key {
    if (!this.isPrivate()) return this;

    const secretPrimary = this.primaryKey as SecretKeyPacket;
    const publicPrimary = secretPrimary.publicKey;

    const publicSubkeys: Subkey[] = this.subkeys.map((s) => {
      if (s.keyPacket instanceof SecretSubkeyPacket) {
        const pubSubkeyPacket = s.keyPacket.publicKey as PublicSubkeyPacket;
        return new Subkey(pubSubkeyPacket, s.bindingSignature, s.revocationSignatures);
      }
      return s;
    });

    return new Key({
      primaryKey: publicPrimary,
      users: this.users,
      subkeys: publicSubkeys,
      directSignatures: this.directSignatures,
      revocations: this.revocations
    });
  }

  async encrypt(passphrase: string): Promise<Key> {
    if (!this.isPrivate()) {
      throw new PGPKeyError('Cannot encrypt public key');
    }
    const secPrimary = this.primaryKey as SecretKeyPacket;
    secPrimary.encrypt(passphrase);

    for (const subkey of this.subkeys) {
      if (subkey.keyPacket instanceof SecretSubkeyPacket) {
        subkey.keyPacket.encrypt(passphrase);
      }
    }
    return this;
  }

  async decrypt(passphrase: string): Promise<Key> {
    if (!this.isPrivate()) {
      return this;
    }
    const secPrimary = this.primaryKey as SecretKeyPacket;
    secPrimary.decrypt(passphrase);

    for (const subkey of this.subkeys) {
      if (subkey.keyPacket instanceof SecretSubkeyPacket) {
        subkey.keyPacket.decrypt(passphrase);
      }
    }
    return this;
  }

  async revoke(
    reason: string = 'Key revoked',
    code: RevocationReasonCode = RevocationReasonCode.KeySuperceded
  ): Promise<{ key: Key; revocationCertificate: string }> {
    if (!this.isPrivate()) {
      throw new PGPKeyError('Cannot generate revocation certificate without private key');
    }

    const secPrimary = this.primaryKey as SecretKeyPacket;
    if (!secPrimary.isDecrypted) {
      throw new PGPKeyError('Private key must be decrypted to revoke');
    }

    const hashData = getKeyRevocationData(secPrimary.publicKey);
    const revSig = signPacket(
      secPrimary,
      SignatureType.KeyRevocation,
      hashData,
      [
        SubpacketBuilder.signatureCreationTime(new Date()),
        SubpacketBuilder.revocationReason(code, reason)
      ]
    );

    this.revocations.push(revSig);

    // Format revocation certificate armor
    const revArmor = armor(ArmorType.PublicKey, revSig.serialize(), {
      Comment: 'Revocation Certificate'
    });

    return { key: this, revocationCertificate: revArmor };
  }
}
