import { HashAlgorithm } from '../types/enums.js';
import { formatCleartextSignedMessage, parseCleartextSignedMessage, canonicalizeCleartext } from '../armor/cleartext.js';
import { Signature } from './signature.js';
import { SignaturePacket } from '../packet/signature.js';

export class CleartextMessage {
  text: string;
  signature?: Signature;
  hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256;

  constructor(text: string, signature?: Signature, hashAlgorithm: HashAlgorithm = HashAlgorithm.SHA256) {
    this.text = text;
    this.signature = signature;
    this.hashAlgorithm = hashAlgorithm;
  }

  static fromText(text: string): CleartextMessage {
    return new CleartextMessage(text);
  }

  static read(armored: string): CleartextMessage {
    const parsed = parseCleartextSignedMessage(armored);
    const signature = Signature.fromArmored(parsed.signatureArmor);
    return new CleartextMessage(parsed.text, signature, parsed.hashAlgorithm);
  }

  getText(): string {
    return this.text;
  }

  getOriginalText(): string {
    return this.text;
  }

  getSignature(): SignaturePacket | undefined {
    return this.signature?.packet;
  }

  async armor(): Promise<string> {
    if (!this.signature) {
      throw new Error('Cannot armor CleartextMessage without a signature');
    }
    const sigArmor = await this.signature.armor();
    return formatCleartextSignedMessage(this.text, sigArmor, this.hashAlgorithm);
  }
}
