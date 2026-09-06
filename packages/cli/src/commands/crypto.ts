import PGPJS from "@pgpjs/core";
import fs from "node:fs";

export async function runEncrypt(inputPath: string, keyPath: string, outputPath?: string): Promise<void> {
  if (!fs.existsSync(inputPath)) {
    console.error(`Input file not found: ${inputPath}`);
    process.exit(1);
  }
  if (!fs.existsSync(keyPath)) {
    console.error(`Public key file not found: ${keyPath}`);
    process.exit(1);
  }

  const data = fs.readFileSync(inputPath, "utf8");
  const key = fs.readFileSync(keyPath, "utf8");

  const encrypted = await PGPJS.encrypt({
    text: data,
    to: key
  });

  const out = outputPath || `${inputPath}.pgp`;
  fs.writeFileSync(out, encrypted as string, "utf8");
  console.log(`✓ Encrypted output written to ${out}`);
}

export async function runDecrypt(inputPath: string, keyPath: string, passphrase?: string, outputPath?: string): Promise<void> {
  if (!fs.existsSync(inputPath)) {
    console.error(`Input file not found: ${inputPath}`);
    process.exit(1);
  }
  if (!fs.existsSync(keyPath)) {
    console.error(`Private key file not found: ${keyPath}`);
    process.exit(1);
  }

  const cipher = fs.readFileSync(inputPath, "utf8");
  const key = fs.readFileSync(keyPath, "utf8");

  const res = await PGPJS.decrypt({
    message: cipher,
    privateKey: key,
    passphrase
  });

  const out = outputPath || inputPath.replace(/\.pgp$/, "");
  fs.writeFileSync(out, res.text ?? res.data);
  console.log(`✓ Decrypted output written to ${out}`);
}
