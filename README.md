# PGPJS

[![npm version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://www.npmjs.com/package/@pgpjs/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue.svg)](https://www.typescriptlang.org/)
[![Tests](https://img.shields.io/badge/tests-76%20passed-brightgreen.svg)]()

> **OpenPGP Without the Complexity.**
> Production-ready, RFC 9580-First TypeScript toolkit for Node.js, Browsers, React, Next.js, and Edge environments.

---

## Why PGPJS?

OpenPGP is historically powerful, but often notoriously complex for developers to integrate. **PGPJS** changes that:

1. **Zero-Config Developer CLI (`npx pgpjs init`)**:
   Automatically detects your framework (Next.js App/Pages Router, React, Vite, Node.js, Express, Hono, Astro), TypeScript configuration, and directory layout (`src/`, `lib/`), scaffolding tailored, type-safe integration code in seconds.
2. **Simplified High-Level API (`PGPJS.seal()` / `PGPJS.open()`)**:
   Pass strings, objects, or arrays directly. PGPJS automatically serializes, signs, encrypts, verifies, and unpacks back to your original JavaScript types.
3. **Next.js End-to-End Encrypted Routes (`pgp()`)**:
   Route Handler wrapper that automatically decrypts requests, verifies client signatures, passes typed `{ data, sender }` to your handler, and encrypts the response.
4. **RFC 9580-First Architecture**:
   Built from the ground up on the modern 2024 OpenPGP standard (**RFC 9580**): **Ed25519** for signatures, **X25519** for encryption, **Argon2** for S2K key derivation, and **AES-256**. Legacy RFC 4880 (RSA, SHA-1 fingerprints, v1 MDC) is maintained strictly for backward compatibility.
5. **Strictly Modular Cryptography Engine**:
   `crypto/` is decoupled into isolated modules (`random/`, `hash/`, `symmetric/`, `asymmetric/`, `s2k/`, `cfb/`), making algorithms effortlessly pluggable without touching the OpenPGP packet parser.

---

## Monorepo Packages

| Package | Description | Version |
|---|---|---|
| [`@pgpjs/core`](./packages/core) | Universal RFC 9580 engine, high-level API (`seal`/`open`, `encryptJSON`), packets, keys, and streams | `0.1.0` |
| [`@pgpjs/cli`](./packages/cli) | Developer CLI: `pgpjs init`, `pgpjs doctor`, `pgpjs key generate`, and file encryption | `0.1.0` |
| [`@pgpjs/next`](./packages/next) | Next.js App Router route middleware (`pgp()`), Server Actions, and client fetcher (`secureRequest`) | `0.1.0` |
| [`@pgpjs/node`](./packages/node) | Node.js filesystem adapters and Node.js `Readable` / `Writable` streaming pipelines | `0.1.0` |
| [`@pgpjs/react`](./packages/react) | Idiomatic React hooks (`useKey`, `useEncryption`, `useDecryption`) and `PGPProvider` | `0.1.0` |

---

## Quickstart

### Step 1: Install & Initialize

In any existing project, simply run:

```bash
npm install @pgpjs/core
npx pgpjs init
```

The CLI inspects your project and scaffolds your integration:
```
🔍 Detecting project environment...
  ✓ TypeScript detected
  ✓ NEXT-APP framework detected
  ✓ src/ directory structure detected

📦 Creating PGPJS integration...
  ✓ src/lib/pgpjs/index.ts
  ✓ src/lib/pgpjs/client.ts
  ✓ src/lib/pgpjs/server.ts
  ✓ pgpjs.config.ts

✨ PGPJS initialized successfully!
```

---

### Step 2: Use in Your Application

```typescript
import PGPJS from "@/lib/pgpjs";

// 1. Generate an RFC 9580 keypair (Ed25519 / X25519)
const keys = await PGPJS.generateKey({
  name: "Alice",
  email: "alice@example.com"
});

// 2. Seal data (accepts objects, strings, arrays)
const ciphertext = await PGPJS.seal({ user: "Bob", balance: 500 }, {
  to: keys.publicKey
});

// 3. Open data
const data = await PGPJS.open(ciphertext, {
  privateKey: keys.privateKey
});

console.log(data.balance); // 500
```

---

## Next.js Route Handler Middleware

Build end-to-end encrypted API routes with zero boilerplate:

```typescript
// app/api/payment/route.ts
import { pgp } from "@pgpjs/next/server";

export const POST = pgp(async ({ data, sender }) => {
  // data is automatically decrypted and typed!
  // sender contains verified client signature metadata
  console.log("Received payment request:", data, "from:", sender?.fingerprint);

  return {
    status: "confirmed",
    transactionId: "tx_123456"
  };
}, {
  privateKey: process.env.PGP_SERVER_PRIVATE_KEY,
  requireSignature: true
});
```

And in your client component:

```typescript
"use client";
import { secureRequest } from "@pgpjs/next/client";

const response = await secureRequest({
  url: "/api/payment",
  body: { amount: 500, recipient: "Alice" },
  encryptWith: serverPublicKeyArmor,
  signWith: clientPrivateKeyArmor
});
```

---

## Developer CLI Commands

```bash
# Auto-detect project & configure PGPJS
npx pgpjs init

# Audit runtime, WebCrypto, and security policy
npx pgpjs doctor

# Generate an RFC 9580 Ed25519/X25519 keypair
npx pgpjs key generate --name "Alice" --email "alice@example.com" --out-public alice.pub --out-private alice.sec

# Inspect key fingerprint, algorithms, and subkeys
npx pgpjs key inspect alice.pub

# Command-line file encryption & decryption
npx pgpjs encrypt secret.txt --to alice.pub --out secret.txt.pgp
npx pgpjs decrypt secret.txt.pgp --key alice.sec --out secret.txt
```

---

## Modular Cryptography Engine

The cryptographic layer in `packages/core/src/crypto/` is strictly modular:

```
crypto/
├── random/          # CSPRNG via crypto.getRandomValues
├── hash/            # SHA-256, SHA-512, SHA-384, SHA-224, SHA-1, RIPEMD-160
├── symmetric/       # AES-128, AES-192, AES-256 block operations
├── asymmetric/
│   ├── rsa/         # RSA 2048/3072/4096-bit with blinding
│   ├── ed25519/     # RFC 9580 / RFC 6637 Ed25519 EdDSA
│   ├── x25519/      # RFC 9580 / RFC 6637 X25519 ECDH + AES Key Wrap
│   └── ecdsa/       # NIST curves P-256, P-384, P-521
├── s2k/             # Simple, Salted, Iterated (RFC 4880), and Argon2 (RFC 9580)
└── cfb/             # OpenPGP CFB mode with 2-byte prefix check & resync
```

---

## Testing & Verification

```bash
# Build all packages
npm run build

# Run 76 automated tests across 14 test suites
npm test
```

---

## License

[MIT](./LICENSE) © 2026 PGPJS Contributors
