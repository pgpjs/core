import PGPJS from "@pgpjs/core";
import fs from "node:fs";

export async function runKeyGenerate(args: {
  name?: string;
  email?: string;
  passphrase?: string;
  outPublic?: string;
  outPrivate?: string;
}): Promise<void> {
  const name = args.name || "PGPJS User";
  const email = args.email || "user@pgpjs.dev";

  console.log(`Generating RFC 9580 Ed25519/X25519 key pair for "${name} <${email}>"...`);
  const keys = await PGPJS.generateKey({
    name,
    email,
    passphrase: args.passphrase
  });

  const pubArmor = keys.publicKey.armor();
  const privArmor = keys.privateKey.armor();

  if (args.outPublic) {
    fs.writeFileSync(args.outPublic, pubArmor, "utf8");
    console.log(`✓ Public key written to ${args.outPublic}`);
  } else {
    console.log("\n--- PUBLIC KEY ---");
    console.log(pubArmor);
  }

  if (args.outPrivate) {
    fs.writeFileSync(args.outPrivate, privArmor, "utf8");
    console.log(`✓ Private key written to ${args.outPrivate}`);
  } else {
    console.log("\n--- PRIVATE KEY ---");
    console.log(privArmor);
  }
}

export async function runKeyInspect(filePath: string): Promise<void> {
  if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    process.exit(1);
  }
  const content = fs.readFileSync(filePath, "utf8");
  const info = await PGPJS.inspectKey(content);

  console.log("\n🔑 OpenPGP Key Inspection Report:");
  console.log(`  Fingerprint: ${info.fingerprint}`);
  console.log(`  Key ID:      ${info.keyID}`);
  console.log(`  Algorithm:   ${info.algorithm}`);
  console.log(`  Created:     ${info.createdAt.toISOString()}`);
  console.log(`  Expires:     ${info.expiresAt ? info.expiresAt.toISOString() : "Never"}`);
  console.log(`  Revoked:     ${info.revoked ? "YES" : "No"}`);
  console.log(`  User IDs:    ${info.users.join(", ")}`);
  console.log(`  Subkeys:     ${info.subkeys.length} subkey(s)`);
  for (const s of info.subkeys) {
    console.log(`    - ID: ${s.keyID} (${s.algorithm})`);
  }
  console.log();
}
