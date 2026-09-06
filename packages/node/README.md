# @pgpjs/node

Node.js adapters, filesystem helpers, and streaming pipelines for PGPJS.

## Installation

```bash
npm install @pgpjs/core @pgpjs/node
```

## Features

- **Filesystem Utilities**: `encryptFile`, `decryptFile`, `signFile`, `verifyFile` for memory-efficient disk-to-disk OpenPGP processing.
- **Node.js Streams**: `createNodeEncryptStream`, `createNodeDecryptStream` bridging OpenPGP Web Streams with Node `stream.Readable` and `stream.Writable`.

## Usage

```typescript
import { encryptFile, decryptFile } from "@pgpjs/node";
import { readKey } from "@pgpjs/core";

const publicKey = await readKey({ armoredKey: pubKeyArmor });
const privateKey = await readKey({ armoredKey: privKeyArmor });

await encryptFile({
  inputPath: "data.csv",
  outputPath: "data.csv.pgp",
  encryptionKeys: publicKey
});

await decryptFile({
  inputPath: "data.csv.pgp",
  outputPath: "restored.csv",
  decryptionKeys: privateKey
});
```

## License

MIT
