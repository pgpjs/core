import { describe, it, expect, beforeEach, afterEach } from "vitest";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { detectProject } from "../../packages/cli/src/detector.js";
import { generateProjectFiles, writeGeneratedFiles } from "../../packages/cli/src/scaffold.js";

describe("PGPJS CLI (@pgpjs/cli)", () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pgpjs-cli-test-"));
  });

  afterEach(() => {
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("detects a Next.js App Router project and generates client/server isolated files", () => {
    // Create Next.js mock project
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "my-next-app",
        dependencies: { next: "15.0.0", react: "19.0.0" }
      })
    );
    fs.writeFileSync(path.join(tempDir, "tsconfig.json"), "{}");
    fs.mkdirSync(path.join(tempDir, "src/app"), { recursive: true });

    const info = detectProject(tempDir);
    expect(info.framework).toBe("next-app");
    expect(info.isTypeScript).toBe(true);
    expect(info.hasSrcDir).toBe(true);
    expect(info.alias).toBe("@/lib/pgpjs");

    const files = generateProjectFiles(info);
    const filePaths = files.map((f) => f.relativePath);

    expect(filePaths).toContain("src/lib/pgpjs/index.ts");
    expect(filePaths).toContain("src/lib/pgpjs/client.ts");
    expect(filePaths).toContain("src/lib/pgpjs/server.ts");
    expect(filePaths).toContain("pgpjs.config.ts");

    const clientFile = files.find((f) => f.relativePath === "src/lib/pgpjs/client.ts");
    expect(clientFile?.content).toContain('"use client";');
    expect(clientFile?.content).toContain("@pgpjs/next/client");

    const serverFile = files.find((f) => f.relativePath === "src/lib/pgpjs/server.ts");
    expect(serverFile?.content).toContain('import "server-only";');
    expect(serverFile?.content).toContain("@pgpjs/next/server");

    // Write to disk
    const written = writeGeneratedFiles(tempDir, files);
    expect(written.length).toBe(4);
    expect(fs.existsSync(path.join(tempDir, "src/lib/pgpjs/index.ts"))).toBe(true);
  });

  it("detects a React/Vite project and generates React hooks integration", () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "my-vite-app",
        devDependencies: { vite: "6.0.0" },
        dependencies: { react: "19.0.0" }
      })
    );
    fs.writeFileSync(path.join(tempDir, "tsconfig.json"), "{}");

    const info = detectProject(tempDir);
    expect(info.framework).toBe("vite");
    expect(info.hasSrcDir).toBe(false);

    const files = generateProjectFiles(info);
    const indexFile = files.find((f) => f.relativePath === "lib/pgpjs/index.ts");
    expect(indexFile?.content).toContain("@pgpjs/react");
  });

  it("detects a Node.js project and generates Node adapter integration", () => {
    fs.writeFileSync(
      path.join(tempDir, "package.json"),
      JSON.stringify({
        name: "my-node-service"
      })
    );

    const info = detectProject(tempDir);
    expect(info.framework).toBe("node");
    expect(info.isTypeScript).toBe(false);

    const files = generateProjectFiles(info);
    const indexFile = files.find((f) => f.relativePath === "lib/pgpjs/index.js");
    expect(indexFile?.content).toContain("@pgpjs/node");
  });
});
