import { Key } from "../key/key.js";
import { generateKeyPair, readKey, KeyPairResult } from "../key/index.js";
import { encrypt } from "../api/encrypt.js";
import { decrypt } from "../api/decrypt.js";
import { sign } from "../api/sign.js";
import { verify } from "../api/verify.js";
import { inspectKey, KeyInfo } from "../inspection/index.js";
import { createKeyStore, KeyStore, KeyStoreOptions } from "../store/index.js";
import { findKey, FindKeyOptions } from "../discovery/index.js";
import { SecurityPolicy, DEFAULT_SECURITY_POLICY, validatePolicyKey } from "../policy/index.js";
import { utf8ToBytes, bytesToUtf8 } from "../utils/bytes.js";
import { DecryptResult, EncryptOptions, DecryptOptions, SignOptions, VerifyOptions } from "../types/interfaces.js";

export interface PGPJSConfig {
  policy?: SecurityPolicy;
  storage?: KeyStoreOptions;
  worker?: boolean;
}

export interface SealOptions {
  to: Key | string | Array<Key | string>;
  from?: Key | string;
  passphrase?: string;
  format?: "armored" | "binary";
}

export interface OpenOptions {
  privateKey: Key | string;
  passphrase?: string;
  from?: Key | string | Array<Key | string>;
}

export class PGPJS {
  readonly policy: SecurityPolicy;
  private keyStorePromise?: Promise<KeyStore>;

  constructor(config: PGPJSConfig = {}) {
    this.policy = { ...DEFAULT_SECURITY_POLICY, ...config.policy };
    if (config.storage) {
      this.keyStorePromise = createKeyStore(config.storage);
    }
  }

  create(config: PGPJSConfig = {}): PGPJS {
    return new PGPJS(config);
  }

  static create(config: PGPJSConfig = {}): PGPJS {
    return new PGPJS(config);
  }

  /**
   * Generates a modern RFC 9580 key pair (Ed25519/X25519 by default).
   */
  async generateKey(options: {
    name: string;
    email?: string;
    comment?: string;
    passphrase?: string;
    type?: "ecc" | "rsa";
    curve?: "ed25519" | "curve25519" | "p256" | "p384" | "p521";
    rsaBits?: 2048 | 3072 | 4096;
  }): Promise<KeyPairResult> {
    const userIDs = [{
      name: options.name,
      email: options.email,
      comment: options.comment
    }];
    return generateKeyPair({
      userIDs,
      passphrase: options.passphrase,
      type: options.type ?? "ecc",
      curve: options.curve ?? "ed25519",
      rsaBits: options.rsaBits ?? 2048
    });
  }

  /**
   * High-level PGPJS.seal(): Encrypts and optionally signs any payload (object, string, or binary).
   */
  async seal(data: any, options: SealOptions): Promise<string | Uint8Array> {
    // 1. Resolve recipient encryption keys
    const recipientInputs = Array.isArray(options.to) ? options.to : [options.to];
    const encryptionKeys: Key[] = [];
    for (const item of recipientInputs) {
      const k = item instanceof Key ? item : await readKey({ armoredKey: item });
      validatePolicyKey(k, this.policy);
      encryptionKeys.push(k);
    }

    // 2. Resolve optional signing key
    let signingKeys: Key | undefined;
    if (options.from) {
      signingKeys = options.from instanceof Key ? options.from : await readKey({ armoredKey: options.from });
      if (options.passphrase && !signingKeys.isDecrypted) {
        await signingKeys.decrypt(options.passphrase);
      }
      validatePolicyKey(signingKeys, this.policy);
    }

    // 3. Encode data with envelope prefix
    let payloadText: string;
    if (typeof data === "string") {
      payloadText = "str:" + data;
    } else if (data instanceof Uint8Array) {
      payloadText = "bin:" + Buffer.from(data).toString("base64");
    } else {
      payloadText = "json:" + JSON.stringify(data);
    }

    return encrypt({
      message: payloadText,
      encryptionKeys,
      signingKeys,
      format: options.format ?? "armored"
    });
  }

  /**
   * High-level PGPJS.open(): Decrypts and unpacks sealed payload to its original JavaScript type.
   */
  async open<T = any>(ciphertext: string | Uint8Array, options: OpenOptions): Promise<T> {
    const secKey = options.privateKey instanceof Key
      ? options.privateKey
      : await readKey({ armoredKey: options.privateKey });

    if (options.passphrase && !secKey.isDecrypted) {
      await secKey.decrypt(options.passphrase);
    }

    let verificationKeys: Key[] | undefined;
    if (options.from) {
      const inputs = Array.isArray(options.from) ? options.from : [options.from];
      verificationKeys = [];
      for (const item of inputs) {
        verificationKeys.push(item instanceof Key ? item : await readKey({ armoredKey: item }));
      }
    }

    const res = await decrypt({
      message: ciphertext,
      decryptionKeys: secKey,
      verificationKeys
    });

    if (this.policy.requireSignature && verificationKeys) {
      const hasValidSig = res.signatures.some((s) => s.valid);
      if (!hasValidSig) {
        throw new Error("Signature verification failed: no valid signature under current policy");
      }
    }

    const text = res.text ?? bytesToUtf8(res.data);

    if (text.startsWith("json:")) {
      return JSON.parse(text.slice(5)) as T;
    } else if (text.startsWith("str:")) {
      return text.slice(4) as unknown as T;
    } else if (text.startsWith("bin:")) {
      return Buffer.from(text.slice(4), "base64") as unknown as T;
    }

    // Fallback if not prefixed
    try {
      return JSON.parse(text) as T;
    } catch {
      return text as unknown as T;
    }
  }

  /**
   * Encrypts a JSON-serializable object or value.
   */
  async encryptJSON<T = any>(data: T, options: { to: Key | string; from?: Key | string; passphrase?: string }): Promise<string> {
    return this.seal(data, { to: options.to, from: options.from, passphrase: options.passphrase, format: "armored" }) as Promise<string>;
  }

  /**
   * Decrypts ciphertext and parses as JSON.
   */
  async decryptJSON<T = any>(ciphertext: string | Uint8Array, options: OpenOptions): Promise<T> {
    return this.open<T>(ciphertext, options);
  }

  /**
   * Universal encrypt helper with shorthand options (to, text, from).
   */
  async encrypt(options: {
    message?: any;
    text?: string;
    to?: any;
    encryptionKeys?: any;
    from?: any;
    signingKeys?: any;
    passwords?: any;
    format?: "armored" | "binary";
  }): Promise<string | Uint8Array> {
    const rawMessage = options.text ?? options.message;
    const rawKeys = options.to ?? options.encryptionKeys;
    const rawSigners = options.from ?? options.signingKeys;

    return encrypt({
      message: rawMessage,
      encryptionKeys: rawKeys,
      signingKeys: rawSigners,
      passwords: options.passwords,
      format: options.format ?? "armored"
    });
  }

  /**
   * Universal decrypt helper with shorthand options (privateKey, from).
   */
  async decrypt(options: {
    message: any;
    privateKey?: any;
    decryptionKeys?: any;
    passphrase?: string;
    passwords?: any;
    from?: any;
    verificationKeys?: any;
  }): Promise<DecryptResult> {
    let decKeys = options.privateKey ?? options.decryptionKeys;
    if (decKeys) {
      if (typeof decKeys === "string") {
        decKeys = await readKey({ armoredKey: decKeys });
      }
      if (options.passphrase && decKeys instanceof Key && !decKeys.isDecrypted) {
        await decKeys.decrypt(options.passphrase);
      }
    }

    return decrypt({
      message: options.message,
      decryptionKeys: decKeys,
      passwords: options.passwords,
      verificationKeys: options.from ?? options.verificationKeys
    });
  }

  /**
   * Developer-friendly verify() with simplified result object.
   */
  async verify(message: any, options: { key?: any; verificationKeys?: any; signature?: any }): Promise<{
    valid: boolean;
    signer?: string;
    fingerprint?: string;
    createdAt?: Date;
    signatures: any[];
  }> {
    const keys = options.key ?? options.verificationKeys;
    const res = await verify({
      message,
      verificationKeys: keys,
      signature: options.signature
    });

    const primarySig = res.signatures[0];
    return {
      valid: primarySig ? primarySig.valid : false,
      signer: primarySig ? primarySig.keyID : undefined,
      fingerprint: primarySig ? primarySig.fingerprint : undefined,
      createdAt: primarySig && primarySig.signature ? primarySig.signature.creationTime : undefined,
      signatures: res.signatures
    };
  }

  async inspectKey(key: Key | string | Uint8Array): Promise<KeyInfo> {
    return inspectKey(key);
  }

  async findKey(options: FindKeyOptions): Promise<Key | null> {
    return findKey(options);
  }

  async createKeyStore(options?: KeyStoreOptions): Promise<KeyStore> {
    return createKeyStore(options);
  }
}

// Export default singleton instance for immediate use: import PGPJS from "@pgpjs/core"
const defaultPGPJS = new PGPJS();
export default defaultPGPJS;
