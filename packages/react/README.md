# @pgpjs/react

Idiomatic React hooks and context provider for client-side OpenPGP operations.

## Installation

```bash
npm install @pgpjs/core @pgpjs/react
```

## Features

- **`PGPProvider` & `usePGP`**: Centralized config and default key storage context.
- **`useKey`**: Asynchronously parses and loads armored or binary OpenPGP keys.
- **`useKeyGeneration`**: Key generation state management (loading, errors, keypair).
- **`useEncryption`**: Message and file encryption hook with reactive status.
- **`useDecryption`**: Decryption and signature verification hook.
- **`useSign` & `useVerify`**: Digital signature hooks.

## Usage

```tsx
import { PGPProvider, useEncryption, useKey } from "@pgpjs/react";

function MessageEncrypter({ recipientArmoredKey }: { recipientArmoredKey: string }) {
  const { key: recipientKey } = useKey({ armoredKey: recipientArmoredKey });
  const { encryptMessage, loading, result, error } = useEncryption();

  return (
    <div>
      <button 
        disabled={loading || !recipientKey} 
        onClick={() => encryptMessage({ message: "Secret", encryptionKeys: recipientKey! })}
      >
        Encrypt
      </button>
      {result && <p>{result as string}</p>}
    </div>
  );
}
```

## License

MIT
