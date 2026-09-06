# @pgpjs/core

Universal, pure TypeScript OpenPGP cryptography engine compliant with RFC 4880, RFC 6637, and RFC 9580.

## Installation

```bash
npm install @pgpjs/core
```

## Features

- **Public-Key Cryptography**: Ed25519 (EdDSA), Curve25519 / X25519 (ECDH session key wrapping with AES Key Wrap), NIST curves (P-256, P-384, P-521), RSA (2048/3072/4096-bit with blinding).
- **Symmetric Ciphers**: AES-128, AES-192, AES-256 in OpenPGP-CFB mode with 2-byte prefix check and resynchronization.
- **Hash Algorithms**: SHA-256, SHA-512, SHA-384, SHA-224, SHA-1, RIPEMD-160.
- **Key Derivation (S2K)**: Simple, Salted, Iterated and Salted (RFC 4880), and Argon2.
- **MDC Integrity Protection**: Tag 18 / Tag 19 modification detection code with SHA-1 validation.
- **Radix-64 ASCII Armor**: CRC-24 checksums and cleartext signature message framing.
- **Compression**: Deflate (ZIP) and ZLIB via `fflate`.
- **Web Streams**: WHATWG `ReadableStream` and `WritableStream` support for chunked message encryption/decryption.

## Usage

```typescript
import { generateKeyPair, encrypt, decrypt, readKey } from "@pgpjs/core";

// Generate an ECC key pair
const { privateKey, publicKey } = await generateKeyPair({
  userIDs: [{ name: "Alice", email: "alice@example.com" }],
  type: "ecc",
  curve: "ed25519"
});

// Encrypt
const ciphertext = await encrypt({
  message: "Hello World",
  encryptionKeys: publicKey
});

// Decrypt
const { text } = await decrypt({
  message: ciphertext,
  decryptionKeys: privateKey
});
```

## License

MIT
