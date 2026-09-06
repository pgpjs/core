# PGPJS Architecture & Design

## 1. Architectural Philosophy

PGPJS is designed as a modular, lightweight, modern TypeScript library implementing the OpenPGP standard (**RFC 4880**, **RFC 6637**, and **RFC 9580**).

Key principles:
1. **Zero Native C/C++ Addons**: Eliminates compilation issues, platform incompatibilities (Node vs Web vs Edge vs React Native), and C-level memory vulnerabilities.
2. **First-Principles Standard Compliance**: Fully implements the RFC binary packet layout, OpenPGP CFB cipher mode, S2K string-to-key derivations, Radix-64 ASCII armor, and MPI serialization.
3. **Audited Cryptographic Foundations**: Primitives rely on audited implementations from the [`@noble`](https://github.com/paulmillr) family (`@noble/hashes`, `@noble/curves`, `@noble/ciphers`) and standard WebCrypto CSPRNG.
4. **Platform Agnostic & Framework First**:
   - Universal core package (`@pgpjs/core`) works in any modern JavaScript runtime.
   - Tailored bindings for Node.js (`@pgpjs/node`), React (`@pgpjs/react`), and Next.js (`@pgpjs/next`).

---

## 2. Monorepo Package Topology

```
pgpjs/
├── packages/
│   ├── core/           # Universal OpenPGP engine (WebCrypto, noble, packets, streams)
│   ├── node/           # Node.js file system adapters and readable/writable stream pipelines
│   ├── react/          # React hooks (useKey, useEncryption) and PGPProvider context
│   └── next/           # Next.js App Router helpers (client/server boundary isolated)
```

---

## 3. Core Engine Pipeline

### 3.1 Packet Engine

The OpenPGP format is a sequence of discrete binary packets. PGPJS parses and emits both Old Format (RFC 4880 Section 4.2.1) and New Format (Section 4.2.2) packet headers:

- **Key Packets**:
  - `PublicKeyPacket` (Tag 6) & `PublicSubkeyPacket` (Tag 14)
  - `SecretKeyPacket` (Tag 5) & `SecretSubkeyPacket` (Tag 7)
  - Stores creation timestamp, public-key algorithm, and algorithm-specific parameters (MPIs for RSA/EdDSA, curve OID and point for ECC).
  - Secret key packets support RFC 4880 S2K-encrypted secret MPIs using AES in raw CFB mode with SHA-1 checksum or 2-byte sum.
- **Signature Packets** (Tag 2):
  - Stores signature type (e.g. 0x00 binary, 0x01 text, 0x10-0x13 user certifications, 0x18 subkey binding, 0x19 primary key binding, 0x20 key revocation).
  - Encodes hashed and unhashed subpacket areas (issuer key ID, issuer fingerprint, creation time, expiration time, key flags, preferred hash/symmetric/compression algorithms).
- **Session Key Packets**:
  - `PublicKeyEncryptedSessionKeyPacket` (Tag 1): Encrypted session key via RSA PKCS#1 v1.5 or Curve25519 ECDH + AES Key Wrap.
  - `SymEncryptedSessionKeyPacket` (Tag 3): Encrypted session key derived from password via S2K.
- **Data Protection Packets**:
  - `SymEncryptedIntegrityProtectedDataPacket` (Tag 18): OpenPGP CFB-encrypted payload followed by a `ModificationDetectionCodePacket` (Tag 19).
  - `LiteralDataPacket` (Tag 11): Unencrypted payload carrying binary or UTF-8 text data.
  - `CompressedDataPacket` (Tag 8): Deflate or ZLIB compressed packet stream.

### 3.2 Cryptographic Subsystems

- **OpenPGP CFB Mode**:
  - OpenPGP specifies an idiosyncratic modification of Cipher Feedback Mode: an initial IV of all zeroes is encrypted to generate a block of pseudorandom keystream, XORed with a random prefix of block size + 2 bytes where the last 2 bytes duplicate the preceding 2 bytes (the resync check). After encrypting this prefix, the CFB shift register is resynchronized with the ciphertext before continuing with plaintext bytes.
  - PGPJS implements this using `@noble/ciphers/aes` block operations, supporting AES-128, AES-192, and AES-256.
- **S2K Key Derivation**:
  - Implements Simple S2K (Type 0), Salted S2K (Type 1), Iterated and Salted S2K (Type 3) with RFC 4880 decoded iteration counting formula: `count = (16 + (c & 15)) << ((c >> 4) + 6)`.
  - Implements Argon2 S2K (Type 4) for modern high-work-factor passphrase hashing.
- **ECC Implementation**:
  - Uses `@noble/curves` for Ed25519, Curve25519/X25519, and NIST curves P-256, P-384, P-521.
  - For Curve25519 ECDH, complies with RFC 6637 / RFC 9580: derives key using ANSI X9.63 KDF with SHA-256 and Key Wrap algorithm (RFC 3394 / NIST SP 800-38F `aeskw`).
- **RSA Implementation**:
  - Key generation via WebCrypto (`crypto.subtle.generateKey`) with PKCS8 export/import.
  - PKCS#1 v1.5 encryption with random padding, decryption with blinding against timing attacks, and deterministic PKCS#1 v1.5 signing with ASN.1 DigestInfo prefixes.

---

## 4. Streaming Architecture

PGPJS uses standard WHATWG Web Streams (`ReadableStream`, `WritableStream`, `TransformStream`) in `@pgpjs/core`. This allows streaming encryption and decryption in:
- Node.js (via `stream.Readable.toWeb` and `@pgpjs/node`)
- Modern web browsers (direct fetch streaming)
- Cloudflare Workers and Edge runtimes

The stream pipeline buffers literal data packets, feeds them into compression, wraps them into OpenPGP CFB encryption with on-the-fly SHA-1 MDC calculation, and terminates with the 22-byte MDC packet.
