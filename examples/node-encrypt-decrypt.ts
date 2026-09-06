/**
 * Example: Complete OpenPGP key generation, message encryption, signing, and verification.
 * Run with: npx tsx examples/node-encrypt-decrypt.ts
 */
import {
  generateKeyPair,
  readKey,
  encrypt,
  decrypt,
  sign,
  verify,
  createCleartextMessage,
  readCleartextMessage
} from "@pgpjs/core";

async function main() {
  console.log("1. Generating Alice (Ed25519) and Bob (Ed25519) Key Pairs...");
  
  const alice = await generateKeyPair({
    userIDs: [{ name: "Alice", email: "alice@example.com" }],
    type: "ecc",
    curve: "ed25519",
    passphrase: "alice-secure-passphrase"
  });

  const bob = await generateKeyPair({
    userIDs: [{ name: "Bob", email: "bob@example.com" }],
    type: "ecc",
    curve: "ed25519"
  });

  console.log("Alice Public Key ID:", alice.publicKey.getKeyID());
  console.log("Bob Public Key ID:", bob.publicKey.getKeyID());

  console.log('\n2. Encrypting secret message from Alice to Bob...');
  // Unlock Alice private key for signing
  await alice.privateKey.decrypt("alice-secure-passphrase");

  const secretMessage = "Confidential project roadmap for 2026";
  const encryptedArmor = await encrypt({
    message: secretMessage,
    encryptionKeys: bob.publicKey,
    signingKeys: alice.privateKey,
    format: "armored"
  });

  console.log("Encrypted Message (ASCII Armor):");
  console.log(encryptedArmor);

  console.log('\n3. Decrypting message as Bob and verifying Alice signature...');
  const decrypted = await decrypt({
    message: encryptedArmor,
    decryptionKeys: bob.privateKey,
    verificationKeys: alice.publicKey
  });

  console.log("Decrypted Plaintext:", decrypted.text);
  console.log("Signature Valid?", decrypted.signatures[0]?.valid);

  console.log('\n4. Creating cleartext signed announcement from Alice...');
  const cleartext = await sign({
    message: "Public Announcement: Security patch v1.0 released.",
    signingKeys: alice.privateKey
  });

  console.log(cleartext);

  const verification = await verify({
    message: cleartext,
    verificationKeys: alice.publicKey
  });
  console.log("Cleartext Signature Verified?", verification.signatures[0]?.valid);
}

main().catch(console.error);
