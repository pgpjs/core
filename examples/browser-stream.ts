/**
 * Example: OpenPGP Web Streams for browser or edge streaming.
 * Uses WHATWG ReadableStream and WritableStream.
 */
import {
  generateKeyPair,
  createEncryptStream,
  createDecryptStream
} from "@pgpjs/core";

async function streamDemo() {
  const keys = await generateKeyPair({
    userIDs: [{ name: "Streamer", email: "stream@example.com" }],
    type: "ecc"
  });

  // Source stream of chunks
  const chunks = ["First chunk of data... ", "Second chunk of data... ", "Final chunk."];
  const inputStream = new ReadableStream<Uint8Array>({
    start(controller) {
      const encoder = new TextEncoder();
      for (const chunk of chunks) {
        controller.enqueue(encoder.encode(chunk));
      }
      controller.close();
    }
  });

  // Encrypt stream
  const encryptStream = createEncryptStream({
    encryptionKeys: keys.publicKey
  });

  const encryptedStream = inputStream.pipeThrough(encryptStream);

  // Decrypt stream
  const decryptStream = createDecryptStream({
    decryptionKeys: keys.privateKey
  });

  const decryptedStream = encryptedStream.pipeThrough(decryptStream);

  // Consume decrypted stream
  const reader = decryptedStream.getReader();
  const decoder = new TextDecoder();
  let result = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    result += decoder.decode(value, { stream: true });
  }

  console.log("Decrypted streamed result:", result);
}

streamDemo().catch(console.error);
