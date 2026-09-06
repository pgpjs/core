import fs from "node:fs";
import path from "node:path";

export interface ProjectInfo {
  cwd: string;
  isTypeScript: boolean;
  framework: "next-app" | "next-pages" | "vite" | "react" | "express" | "hono" | "astro" | "node";
  hasSrcDir: boolean;
  targetDir: string;
  alias: string;
}

export function detectProject(cwd: string = process.cwd()): ProjectInfo {
  const pkgPath = path.join(cwd, "package.json");
  let pkg: any = {};
  if (fs.existsSync(pkgPath)) {
    try {
      pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
    } catch {
      // ignore
    }
  }

  const allDeps = {
    ...(pkg.dependencies || {}),
    ...(pkg.devDependencies || {})
  };

  const isTypeScript = fs.existsSync(path.join(cwd, "tsconfig.json"));
  const hasSrcDir = fs.existsSync(path.join(cwd, "src"));

  let framework: ProjectInfo["framework"] = "node";

  if (allDeps.next) {
    const hasApp = fs.existsSync(path.join(cwd, hasSrcDir ? "src/app" : "app"));
    framework = hasApp ? "next-app" : "next-pages";
  } else if (allDeps.astro) {
    framework = "astro";
  } else if (allDeps.hono) {
    framework = "hono";
  } else if (allDeps.express) {
    framework = "express";
  } else if (allDeps.vite) {
    framework = "vite";
  } else if (allDeps.react) {
    framework = "react";
  }

  const baseDir = hasSrcDir ? "src/lib/pgpjs" : "lib/pgpjs";
  const targetDir = path.join(cwd, baseDir);
  const alias = hasSrcDir ? "@/lib/pgpjs" : "./lib/pgpjs";

  return {
    cwd,
    isTypeScript,
    framework,
    hasSrcDir,
    targetDir,
    alias
  };
}
