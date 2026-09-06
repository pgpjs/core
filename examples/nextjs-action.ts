/**
 * Example: Next.js App Router Integration.
 * Demonstrates clean separation between server actions and client forms.
 */

// --- In a Next.js Server Action file: (e.g. app/actions.ts) ---
import { createServerActionDecrypt, createServerActionSign } from "@pgpjs/next/server";

// Server action decrypter
export const decryptClientSubmission = createServerActionDecrypt({
  privateKey: process.env.SERVER_PRIVATE_KEY || "-----BEGIN PGP PRIVATE KEY BLOCK-----...",
  passphrase: process.env.SERVER_PASSPHRASE
});

// Server action response signer
export const signServerReceipt = createServerActionSign({
  signingKey: process.env.SERVER_PRIVATE_KEY || "-----BEGIN PGP PRIVATE KEY BLOCK-----...",
  passphrase: process.env.SERVER_PASSPHRASE
});

// --- In a Next.js Client Component: (e.g. app/contact-form.tsx) ---
import { encryptForServer } from "@pgpjs/next/client";

export async function submitContactMessage(userMessage: string, serverPublicKeyArmor: string) {
  // 1. Encrypt securely in the browser before sending over the network
  const encryptedPayload = await encryptForServer(userMessage, serverPublicKeyArmor);

  // 2. Invoke Server Action with ONLY encrypted payload
  const result = await decryptClientSubmission(encryptedPayload);
  return result;
}
