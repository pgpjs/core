# @pgpjs/next

Next.js App Router utilities with strict server/client boundary separation.

## Installation

```bash
npm install @pgpjs/core @pgpjs/next
```

## Features

- **Client/Server Isolation**: Separate entrypoints (`@pgpjs/next/client` vs `@pgpjs/next/server`). Client imports never pull private key decryption logic or secret keys into browser JavaScript bundles.
- **Server Utilities (`@pgpjs/next/server`)**:
  - `decryptInRouteHandler(req, options)`: Helper for Next.js Route Handlers.
  - `createServerActionDecrypt(options)`: Generates safe Next.js Server Action decrypter.
  - `createServerActionSign(options)`: Server Action signer.
- **Client Utilities (`@pgpjs/next/client`)**:
  - `encryptForServer(data, serverPublicKeyArmor)`: Zero-leakage client-side payload encrypter.
  - `verifyFromServer(message, serverPublicKeyArmor)`: Verify data sent from the server.

## Usage

### Server Action
```typescript
"use server";
import { createServerActionDecrypt } from "@pgpjs/next/server";

export const handleEncryptedUpload = createServerActionDecrypt({
  privateKey: process.env.SERVER_PRIVATE_KEY!,
  passphrase: process.env.SERVER_PASSPHRASE
});
```

### Client Component
```tsx
"use client";
import { encryptForServer } from "@pgpjs/next/client";
import { handleEncryptedUpload } from "./actions";

export function Form() {
  async function onSubmit(text: string) {
    const ciphertext = await encryptForServer(text, process.env.NEXT_PUBLIC_PGP_KEY!);
    await handleEncryptedUpload(ciphertext);
  }
}
```

## License

MIT
