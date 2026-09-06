# PGPJS Security Model

## 1. Security Principles

PGPJS is built on defense-in-depth principles:
1. **Mandatory Authenticated Encryption**: OpenPGP historic unauthenticated encryption (Tag 9) is inherently vulnerable to ciphertext malleability and chosen-ciphertext attacks (EFAIL attacks). PGPJS defaults to **MDC Integrity-Protected packets (Tag 18 & 19)** and strictly checks MDC validation. Payloads failing MDC check throw a `PGPDecryptionError`.
2. **Cryptographic Blinding for RSA**: RSA private key operations are inherently vulnerable to timing side-channels if modular exponentiation timing leaks private exponent bits. PGPJS implements blinding for RSA operations.
3. **Constant-Time Memory Comparisons**: Comparisons of message digests, MDC tags, and signatures use constant-time byte comparisons (`bytesEqual`) to thwart timing attacks.
4. **CSPRNG Entropy**: Cryptographic keys, session keys, salt, and nonces are drawn exclusively from `crypto.getRandomValues`. Math.random() is strictly prohibited across the codebase.
5. **Memory Safety**: Being 100% TypeScript with zero native C/C++ bindings, PGPJS is inherently protected against memory-safety flaws such as buffer overruns, use-after-free, and pointer corruption.

---

## 2. Supported Algorithms & Recommendations

### Recommended Configuration (Default)
- **Primary / Signing**: Ed25519 (EdDSA)
- **Encryption / Key Agreement**: Curve25519 / X25519 (ECDH) with AES-256 Key Wrap
- **Symmetric Cipher**: AES-256
- **Hash Algorithm**: SHA-256 or SHA-512
- **Key Derivation**: Iterated & Salted S2K or Argon2

### Legacy Compatibility
- **RSA**: Supported (2048, 3072, 4096-bit). 1024-bit RSA is rejected as insecure.
- **SHA-1**: Supported strictly for RFC 4880 compatibility (v4 key fingerprints and MDC calculation as dictated by RFC 4880). SHA-1 is **never** used for new digital signatures.
- **MD5**: Completely disabled and unsupported.

---

## 3. Server/Client Isolation in Next.js & React

In modern fullstack JavaScript frameworks (Next.js, Remix, SvelteKit), developer mistakes can accidentally bundle private keys into client JavaScript bundles sent to the browser.

`@pgpjs/next` provides structural guarantees:
- Separate subpaths: `@pgpjs/next/server` and `@pgpjs/next/client`.
- `@pgpjs/next/client` exports only public-key and verification utilities (`encryptForServer`, `verifyFromServer`).
- Attempting to pass a private key or decrypt within client components causes TypeScript compilation errors.
