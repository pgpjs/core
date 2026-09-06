/**
 * Example: React Component using @pgpjs/react hooks.
 */
import React, { useState } from "react";
import { PGPProvider, useKey, useEncryption, useDecryption } from "@pgpjs/react";

export function SecureMessagingApp({
  recipientPublicKeyArmor,
  userPrivateKeyArmor
}: {
  recipientPublicKeyArmor: string;
  userPrivateKeyArmor: string;
}) {
  const [inputText, setInputText] = useState("");
  const [encryptedOutput, setEncryptedOutput] = useState("");

  const { key: recipientKey, loading: keyLoading } = useKey({ armoredKey: recipientPublicKeyArmor });
  const { key: userKey } = useKey({ armoredKey: userPrivateKeyArmor });
  
  const { encryptMessage, loading: encrypting } = useEncryption();
  const { decryptMessage, loading: decrypting, result: decryptedText } = useDecryption();

  const handleEncrypt = async () => {
    if (!recipientKey) return;
    const cipher = await encryptMessage({
      message: inputText,
      encryptionKeys: recipientKey
    });
    setEncryptedOutput(cipher as string);
  };

  const handleDecrypt = async () => {
    if (!userKey || !encryptedOutput) return;
    await decryptMessage({
      message: encryptedOutput,
      decryptionKeys: userKey
    });
  };

  return (
    <div style={{ padding: "2rem", fontFamily: "sans-serif" }}>
      <h2>PGPJS Secure Messaging</h2>
      {keyLoading && <p>Loading cryptographic keys...</p>}

      <textarea
        rows={4}
        cols={50}
        value={inputText}
        onChange={(e) => setInputText(e.target.value)}
        placeholder="Enter confidential message..."
      />
      <br />
      <button onClick={handleEncrypt} disabled={encrypting || !recipientKey}>
        {encrypting ? "Encrypting..." : "Encrypt"}
      </button>

      {encryptedOutput && (
        <div>
          <h3>Ciphertext:</h3>
          <pre style={{ background: "#f4f4f4", padding: "1rem" }}>{encryptedOutput}</pre>
          <button onClick={handleDecrypt} disabled={decrypting}>
            {decrypting ? "Decrypting..." : "Decrypt with My Key"}
          </button>
        </div>
      )}

      {decryptedText && (
        <div>
          <h3>Decrypted Result:</h3>
          <p><strong>{decryptedText}</strong></p>
        </div>
      )}
    </div>
  );
}

export function App() {
  return (
    <PGPProvider>
      <SecureMessagingApp
        recipientPublicKeyArmor="-----BEGIN PGP PUBLIC KEY BLOCK-----..."
        userPrivateKeyArmor="-----BEGIN PGP PRIVATE KEY BLOCK-----..."
      />
    </PGPProvider>
  );
}
