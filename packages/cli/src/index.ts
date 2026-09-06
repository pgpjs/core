import { runInit } from "./commands/init.js";
import { runDoctor } from "./commands/doctor.js";
import { runKeyGenerate, runKeyInspect } from "./commands/key.js";
import { runEncrypt, runDecrypt } from "./commands/crypto.js";

export * from "./detector.js";
export * from "./scaffold.js";

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "--help" || command === "-h" || command === "help") {
    printHelp();
    return;
  }

  if (command === "--version" || command === "-v") {
    console.log("pgpjs v0.1.0");
    return;
  }

  switch (command) {
    case "init":
      await runInit();
      break;

    case "doctor":
      await runDoctor();
      break;

    case "key": {
      const sub = args[1];
      if (sub === "generate" || sub === "gen") {
        const nameIdx = args.indexOf("--name");
        const emailIdx = args.indexOf("--email");
        const passIdx = args.indexOf("--passphrase");
        const outPubIdx = args.indexOf("--out-public");
        const outPrivIdx = args.indexOf("--out-private");

        await runKeyGenerate({
          name: nameIdx !== -1 ? args[nameIdx + 1] : undefined,
          email: emailIdx !== -1 ? args[emailIdx + 1] : undefined,
          passphrase: passIdx !== -1 ? args[passIdx + 1] : undefined,
          outPublic: outPubIdx !== -1 ? args[outPubIdx + 1] : undefined,
          outPrivate: outPrivIdx !== -1 ? args[outPrivIdx + 1] : undefined
        });
      } else if (sub === "inspect") {
        const file = args[2];
        if (!file) {
          console.error("Usage: pgpjs key inspect <keyfile>");
          process.exit(1);
        }
        await runKeyInspect(file);
      } else {
        console.error("Unknown key command. Available: pgpjs key generate, pgpjs key inspect");
      }
      break;
    }

    case "encrypt": {
      const input = args[1];
      const keyIdx = args.indexOf("--to");
      const outIdx = args.indexOf("--out");
      if (!input || keyIdx === -1) {
        console.error("Usage: pgpjs encrypt <file> --to <pubkey.asc> [--out <output>]");
        process.exit(1);
      }
      await runEncrypt(input, args[keyIdx + 1], outIdx !== -1 ? args[outIdx + 1] : undefined);
      break;
    }

    case "decrypt": {
      const input = args[1];
      const keyIdx = args.indexOf("--key");
      const passIdx = args.indexOf("--passphrase");
      const outIdx = args.indexOf("--out");
      if (!input || keyIdx === -1) {
        console.error("Usage: pgpjs decrypt <file.pgp> --key <privkey.asc> [--passphrase <pwd>] [--out <output>]");
        process.exit(1);
      }
      await runDecrypt(
        input,
        args[keyIdx + 1],
        passIdx !== -1 ? args[passIdx + 1] : undefined,
        outIdx !== -1 ? args[outIdx + 1] : undefined
      );
      break;
    }

    default:
      console.error(`Unknown command: ${command}`);
      printHelp();
      process.exit(1);
  }
}

function printHelp() {
  console.log(`
PGPJS CLI — OpenPGP Without the Complexity (RFC 9580)

Usage:
  pgpjs <command> [options]

Commands:
  init                       Auto-detect framework and scaffold PGPJS integration
  doctor                     Verify environment, WebCrypto, runtime, and security health
  key generate [options]     Generate modern RFC 9580 Ed25519/X25519 key pair
  key inspect <keyfile>      Inspect OpenPGP key packets, fingerprint, and subkeys
  encrypt <file> --to <key>  Encrypt a file using recipient's public key
  decrypt <file> --key <key> Decrypt a file using private key

Options:
  --help, -h                 Show help
  --version, -v              Show version
`);
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
