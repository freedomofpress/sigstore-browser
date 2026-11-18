// Reads the vendored vectors from disk into plain, serializable data, so that the same checks can
// run in Node, Bun and (through vitest's provide/inject) in browsers. Node-only.
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const VECTORS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../vectors");

export type Expected =
  | { result: "accept" }
  | { result: "reject"; code: string; error?: string; message?: string; clause?: string; reason?: string };

export interface ManagedKeyVector {
  id: string;
  category: string;
  parent: string | null;
  bundle: string; // JSON text, exactly as stored
  key: string; // PEM
  artifact: string; // base64
  root: string; // JSON text
  expected: { library: Expected; library_checkpoint_log_binding: Expected; profile: Expected };
}

export interface Corpus {
  managedKey: ManagedKeyVector[];
  // Sigstore's staging trusted root (TUF snapshot), which has retired logs and an RSA CT log key.
  stagingRoot: string;
}

const read = (file: string) => readFileSync(file, "utf8");
const readB64 = (file: string) => readFileSync(file).toString("base64");

// The fields of a manifest.json vector that the checks use; file fields are paths relative to it.
interface ManifestVector {
  id: string;
  category: string;
  parent: string | null;
  bundle: string;
  key: string;
  artifact: string;
  trusted_root: string;
  expected: ManagedKeyVector["expected"];
}

export function loadManagedKeyCorpus(dir = path.join(VECTORS_DIR, "managed-key")): ManagedKeyVector[] {
  const manifest: { vectors: ManifestVector[] } = JSON.parse(read(path.join(dir, "manifest.json")));
  return manifest.vectors.map((v) => ({
    id: v.id,
    category: v.category,
    parent: v.parent,
    bundle: read(path.join(dir, v.bundle)),
    key: read(path.join(dir, v.key)),
    artifact: readB64(path.join(dir, v.artifact)),
    root: read(path.join(dir, v.trusted_root)),
    expected: v.expected,
  }));
}

export function loadCorpus(): Corpus {
  return {
    managedKey: loadManagedKeyCorpus(),
    stagingRoot: read(path.join(VECTORS_DIR, "managed-key", "sources", "trusted_root.staging.json")),
  };
}
