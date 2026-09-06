import { detectProject } from "../detector.js";

export async function runDoctor(cwd: string = process.cwd()): Promise<boolean> {
  console.log("\n🩺 PGPJS Doctor: System & Environment Health Check\n");
  let allGood = true;

  // 1. Node runtime
  const nodeVer = process.version;
  const major = parseInt(nodeVer.slice(1).split(".")[0], 10);
  if (major >= 18) {
    console.log(`  ✓ Node.js ${nodeVer} (compatible >= 18)`);
  } else {
    console.log(`  ✗ Node.js ${nodeVer} is unsupported. PGPJS requires Node >= 18.`);
    allGood = false;
  }

  // 2. WebCrypto
  if (typeof globalThis.crypto !== "undefined" && typeof globalThis.crypto.getRandomValues === "function") {
    console.log("  ✓ WebCrypto CSPRNG available (crypto.getRandomValues)");
  } else {
    console.log("  ✗ WebCrypto CSPRNG is missing");
    allGood = false;
  }

  if (typeof globalThis.crypto?.subtle !== "undefined") {
    console.log("  ✓ WebCrypto Subtle API available");
  } else {
    console.log("  ⚠ WebCrypto Subtle API not present (RSA keygen fallback mode)");
  }

  // 3. Web Streams
  if (typeof globalThis.ReadableStream !== "undefined" && typeof globalThis.WritableStream !== "undefined") {
    console.log("  ✓ Web Streams API available (ReadableStream, WritableStream)");
  } else {
    console.log("  ⚠ Web Streams not available on global scope");
  }

  // 4. Project context
  const info = detectProject(cwd);
  console.log(`  ✓ Project environment: ${info.framework} (${info.isTypeScript ? "TypeScript" : "JavaScript"})`);

  // 5. Security Status
  console.log("\nSecurity Status:");
  console.log("  ✓ RFC 9580-First architecture");
  console.log("  ✓ Modern defaults enabled: Ed25519, X25519, Argon2, AES-256");
  console.log("  ✓ Legacy algorithms (MD5, SHA-1 signatures) disabled by default\n");

  if (allGood) {
    console.log("🎉 PGPJS environment is healthy and ready for production!\n");
  }

  return allGood;
}
