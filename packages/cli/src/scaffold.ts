import fs from "node:fs";
import path from "node:path";
import { ProjectInfo } from "./detector.js";

export interface GeneratedFile {
  relativePath: string;
  content: string;
}

export function generateProjectFiles(info: ProjectInfo): GeneratedFile[] {
  const ext = info.isTypeScript ? "ts" : "js";
  const files: GeneratedFile[] = [];

  const baseDir = info.hasSrcDir ? "src/lib/pgpjs" : "lib/pgpjs";

  if (info.framework === "next-app" || info.framework === "next-pages") {
    // 1. index
    files.push({
      relativePath: `${baseDir}/index.${ext}`,
      content: `import * as PGPJS from "@pgpjs/core";
export default PGPJS;
export * from "@pgpjs/core";
`
    });

    // 2. client
    files.push({
      relativePath: `${baseDir}/client.${ext}`,
      content: `"use client";
import * as PGPJS from "@pgpjs/core";
export default PGPJS;
export * from "@pgpjs/core";
export * from "@pgpjs/next/client";
`
    });

    // 3. server
    files.push({
      relativePath: `${baseDir}/server.${ext}`,
      content: `import "server-only";
import * as PGPJS from "@pgpjs/core";
export default PGPJS;
export * from "@pgpjs/core";
export * from "@pgpjs/next/server";
`
    });
  } else if (info.framework === "react" || info.framework === "vite") {
    files.push({
      relativePath: `${baseDir}/index.${ext}`,
      content: `import * as PGPJS from "@pgpjs/core";
export default PGPJS;
export * from "@pgpjs/core";
export * from "@pgpjs/react";
`
    });
  } else {
    // Node / Express / Hono / Generic
    files.push({
      relativePath: `${baseDir}/index.${ext}`,
      content: `import * as PGPJS from "@pgpjs/core";
export default PGPJS;
export * from "@pgpjs/core";
export * from "@pgpjs/node";
`
    });
  }

  // Configuration file: pgpjs.config.ts / pgpjs.config.js
  files.push({
    relativePath: `pgpjs.config.${ext}`,
    content: `/**
 * PGPJS Project Configuration & Security Policy
 */
export const config = {
  policy: {
    minimumStrength: "modern", // RFC 9580 modern algorithms
    rejectExpiredKeys: true,
    rejectRevokedKeys: true,
    allowLegacyAlgorithms: false
  }
};

export default config;
`
  });

  return files;
}

export function writeGeneratedFiles(cwd: string, files: GeneratedFile[]): string[] {
  const writtenPaths: string[] = [];
  for (const file of files) {
    const fullPath = path.join(cwd, file.relativePath);
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(fullPath, file.content, "utf8");
    writtenPaths.push(file.relativePath);
  }
  return writtenPaths;
}
