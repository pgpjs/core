import { detectProject } from "../detector.js";
import { generateProjectFiles, writeGeneratedFiles } from "../scaffold.js";

export async function runInit(cwd: string = process.cwd()): Promise<void> {
  console.log("\n🔍 Detecting project environment...");
  const info = detectProject(cwd);

  console.log(`  ✓ ${info.isTypeScript ? "TypeScript" : "JavaScript"} detected`);
  console.log(`  ✓ ${info.framework.toUpperCase()} framework detected`);
  if (info.hasSrcDir) {
    console.log("  ✓ src/ directory structure detected");
  }

  console.log("\n📦 Creating PGPJS integration...");
  const files = generateProjectFiles(info);
  const written = writeGeneratedFiles(cwd, files);

  for (const p of written) {
    console.log(`  ✓ ${p}`);
  }

  console.log("\n✨ PGPJS initialized successfully!");
  console.log("\nYou can now use PGPJS anywhere in your code:");
  console.log(`  import PGPJS from "${info.alias}";`);
  console.log("  // or:");
  console.log(`  import { encrypt, decrypt, seal, open } from "${info.alias}";\n`);
}
