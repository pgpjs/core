import { KeyFlag, PublicKeyAlgorithm } from '../types/enums.js';
import { AlgorithmInfo } from '../types/interfaces.js';
import { PublicSubkeyPacket } from '../packet/public-key.js';
import { SecretSubkeyPacket } from '../packet/secret-key.js';
import { SignaturePacket } from '../packet/signature.js';

export class Subkey {
  keyPacket: PublicSubkeyPacket | SecretSubkeyPacket;
  bindingSignature?: SignaturePacket;
  revocationSignatures: SignaturePacket[] = [];

  constructor(
    keyPacket: PublicSubkeyPacket | SecretSubkeyPacket,
    bindingSignature?: SignaturePacket,
    revocationSignatures: SignaturePacket[] = []
  ) {
    this.keyPacket = keyPacket;
    this.bindingSignature = bindingSignature;
    this.revocationSignatures = revocationSignatures;
  }

  isPrivate(): boolean {
    return this.keyPacket instanceof SecretSubkeyPacket;
  }

  isRevoked(): boolean {
    return this.revocationSignatures.length > 0;
  }

  getFingerprint(): string {
    if (this.keyPacket instanceof SecretSubkeyPacket) {
      return this.keyPacket.publicKey.getFingerprintHex();
    }
    return this.keyPacket.getFingerprintHex();
  }

  getKeyID(): string {
    if (this.keyPacket instanceof SecretSubkeyPacket) {
      return this.keyPacket.publicKey.getKeyID();
    }
    return this.keyPacket.getKeyID();
  }

  getCreationTime(): Date {
    if (this.keyPacket instanceof SecretSubkeyPacket) {
      return this.keyPacket.publicKey.creationTime;
    }
    return this.keyPacket.creationTime;
  }

  getExpirationTime(): Date | null {
    if (this.bindingSignature) {
      const exp = this.bindingSignature.getKeyExpirationTime();
      if (exp) return exp;
    }
    return null;
  }

  getKeyFlags(): KeyFlag[] {
    if (!this.bindingSignature) return [];
    return this.bindingSignature.getKeyFlags();
  }

  canEncrypt(): boolean {
    const flags = this.getKeyFlags();
    if (flags.includes(KeyFlag.EncryptCommunications) || flags.includes(KeyFlag.EncryptStorage)) {
      return true;
    }
    const algo = this.keyPacket instanceof SecretSubkeyPacket ? this.keyPacket.publicKey.algorithm : this.keyPacket.algorithm;
    return algo === PublicKeyAlgorithm.RSA || algo === PublicKeyAlgorithm.RSAEncryptOnly || algo === PublicKeyAlgorithm.ECDH;
  }

  canSign(): boolean {
    const flags = this.getKeyFlags();
    if (flags.includes(KeyFlag.SignData)) {
      return true;
    }
    const algo = this.keyPacket instanceof SecretSubkeyPacket ? this.keyPacket.publicKey.algorithm : this.keyPacket.algorithm;
    return algo === PublicKeyAlgorithm.RSA || algo === PublicKeyAlgorithm.RSASignOnly || algo === PublicKeyAlgorithm.EdDSA || algo === PublicKeyAlgorithm.ECDSA;
  }

  getAlgorithmInfo(): AlgorithmInfo {
    const pk = this.keyPacket instanceof SecretSubkeyPacket ? this.keyPacket.publicKey : this.keyPacket;
    const algo = pk.algorithm;
    if (
      algo === PublicKeyAlgorithm.RSA ||
      algo === PublicKeyAlgorithm.RSAEncryptOnly ||
      algo === PublicKeyAlgorithm.RSASignOnly
    ) {
      return { algorithm: 'RSA', bits: pk.n ? pk.n.toString(2).length : 2048 };
    }
    if (algo === PublicKeyAlgorithm.ECDH) {
      return { algorithm: 'ECDH', curve: pk.curve ?? 'curve25519' };
    }
    if (algo === PublicKeyAlgorithm.EdDSA || algo === PublicKeyAlgorithm.Ed25519) {
      return { algorithm: 'EdDSA', curve: pk.curve ?? 'ed25519' };
    }
    if (algo === PublicKeyAlgorithm.ECDSA) {
      return { algorithm: 'ECDSA', curve: pk.curve ?? 'p256' };
    }
    return { algorithm: `Algorithm(${algo})` };
  }
}
