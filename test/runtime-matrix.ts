// Runs the managed-key corpus (strict and default configurations, DSSE/artifact/digest) and the
// sigstore-conformance vectors against the built library, outside any test framework, so the same
// checks run unchanged on Node and Bun:
//
//   npm run build && node test/runtime-matrix.ts && bun test/runtime-matrix.ts
//   NO_NATIVE_ED25519=1 node test/runtime-matrix.ts   # Ed25519 through the @noble/curves fallback
//
// Exits non-zero on any mismatch.
import { checkManagedKeyCorpus, type Lib, type Mismatch } from "./corpus/check.ts";
import { loadCorpus } from "./corpus/data.ts";
import { withoutEd25519 } from "./no-ed25519.ts";

const bun = (globalThis as { Bun?: { version: string } }).Bun;
const runtime = bun ? `bun ${bun.version}` : `node ${process.versions.node}`;

const noble = await import("@freedomofpress/crypto-browser/noble");
const cryptoBrowser = await import("@freedomofpress/crypto-browser");
let ed25519 = "native";
if (process.env.NO_NATIVE_ED25519) {
  const noEd25519 = withoutEd25519(globalThis.crypto.subtle);
  // Install it globally where the runtime allows (Node); Bun's crypto.subtle cannot be replaced.
  try {
    Object.defineProperty(globalThis.crypto, "subtle", { value: noEd25519, configurable: true });
  } catch {
    // Bun: route crypto-browser (which every library helper uses) through it instead.
  }
  // What installEd25519Fallback() does on an engine without Ed25519.
  cryptoBrowser.setSubtle(noble.withEd25519Fallback(noEd25519));
  const subtle = await cryptoBrowser.getSubtle();
  const probe = await subtle.importKey("raw", new Uint8Array(32), { name: "Ed25519" }, true, ["verify"]);
  const fallbackProbe = probe as unknown as { __fallback__?: boolean };
  const usesFallback = fallbackProbe.__fallback__ === true;
  if (!usesFallback) {
    throw new Error("Ed25519 keys are still native; the fallback would not run");
  }
  let direct = "native";
  try {
    await noEd25519.importKey("raw", new Uint8Array(32), { name: "Ed25519" }, true, ["verify"]);
  } catch {
    direct = "rejected";
  }
  ed25519 = `@noble/curves fallback (native Ed25519 ${direct})`;
}

const lib = (await import(new URL("../dist/index.js", import.meta.url).href)) as Lib;
const corpus = loadCorpus();
const mismatches: Mismatch[] = [];
const counts: string[] = [];
for (const mode of ["strict", "default"] as const) {
  for (const how of ["dsse", "artifact", "digest"] as const) {
    const found = await checkManagedKeyCorpus(lib, corpus.managedKey, mode, how);
    counts.push(`managed-key ${mode}/${how}: ${corpus.managedKey.length - found.length}/${corpus.managedKey.length}`);
    mismatches.push(...found);
  }
}

console.log(`${runtime}, Ed25519 ${ed25519}`);
for (const line of counts) console.log(`  ${line}`);
for (const m of mismatches) {
  console.log(`  MISMATCH ${m.how} ${m.id}: expected ${JSON.stringify(m.expected)}, got ${JSON.stringify(m.actual)}`);
}
process.exitCode = mismatches.length ? 1 : 0;
