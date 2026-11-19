// Runs the vendored vectors against the library and reports every outcome that differs from the
// expected one. Runtime-agnostic (Node, Bun, browsers): it receives the library and the data.
import { verifySignatureOverDigest } from "@freedomofpress/crypto-browser/noble";

import type * as library from "../../src/index.ts";
import { base64ToBytes } from "../helpers.ts";
import type { Corpus, Expected, ManagedKeyVector } from "./data.ts";

/** The parts of the library the checks use: the source in tests, the built dist/ in runtime-matrix.ts. */
export type Lib = Pick<typeof library, "ManagedKeyVerifier" | "STRICT_MANAGED_KEY_PROFILE" | "SigstoreVerifier">;

export interface Outcome {
  result: "accept" | "reject";
  code?: string;
  message?: string;
}

export interface Mismatch {
  id: string;
  how: string;
  expected: Expected;
  actual: Outcome;
}

export type Mode = "strict" | "default";
export type How = "dsse" | "artifact" | "digest";

const sha256 = async (data: Uint8Array) => new Uint8Array(await crypto.subtle.digest("SHA-256", data));

// The digest a messageSignature signed: the hash the key implies (SHA-256 for P-256, SHA-384 for
// P-384). DSSE bundles keep SHA-256, matching their in-toto subject digests.
const P256_OID_TLV = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_OID_TLV = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
function hasCurve(der: Uint8Array, oid: number[]): boolean {
  for (let offset = 0; offset + oid.length <= der.length; offset++) {
    const matches = oid.every((byte, index) => der[offset + index] === byte);
    if (matches) {
      return true;
    }
  }
  return false;
}

function blobDigestAlgorithm(key: string): string {
  const encodedKey = key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = base64ToBytes(encodedKey);
  // Trial imports are not portable: Firefox accepts a P-256 key requested as P-384.
  if (hasCurve(der, P384_OID_TLV)) {
    return "SHA-384";
  }
  if (hasCurve(der, P256_OID_TLV)) {
    return "SHA-256";
  }
  throw new Error("unrecognized EC curve in SPKI");
}

async function digestForVector(vector: ManagedKeyVector, artifact: Uint8Array): Promise<Uint8Array> {
  const bundle = JSON.parse(vector.bundle);
  if (!bundle.messageSignature) {
    return sha256(artifact);
  }

  const algorithm = blobDigestAlgorithm(vector.key);
  const digest = await crypto.subtle.digest(algorithm, artifact);
  return new Uint8Array(digest);
}

/** Browser exceptions to the shared profile; its corpus bytes and expectations stay unchanged. */
export const STRICT_MODE_DIFFERENCES: Record<string, { expected: Expected; why: string }> = {
  "p384-duplicate-dsse-envelope-key": {
    expected: { result: "reject", code: "dsse-signature-invalid" },
    why: "JSON.parse keeps the last envelope; callers must reject repeated member names before verification",
  },
};

/**
 * Where the default (upstream-consistent) configuration intentionally differs from sigstore-rust's
 * library defaults ("library" in the manifest). Strict exceptions are listed separately above.
 */
export const DEFAULT_MODE_DIFFERENCES: Record<string, { expected: Expected; why: string }> = {
  "p384-entry-names-another-trusted-log": {
    expected: { result: "reject", code: "checkpoint-signature-invalid" },
    why: "the checkpoint must be signed by the key of the log the entry names, as in the certificate flow",
  },
  "p256-entry-names-another-trusted-log": {
    expected: { result: "reject", code: "checkpoint-signature-invalid" },
    why: "the checkpoint must be signed by the key of the log the entry names, as in the certificate flow",
  },
  "p384-checkpoint-signed-by-other-trusted-log": {
    expected: { result: "reject", code: "checkpoint-signature-invalid" },
    why: "the checkpoint must be signed by the key of the log the entry names, as in the certificate flow",
  },
  "p384-timestamp-removed": {
    expected: { result: "reject", code: "timestamp-count" },
    why: "a verified observer time is required, as in the certificate flow; Rekor v2 entries carry none",
  },
  "p384-timestamp-duplicated": {
    expected: { result: "reject", code: "timestamp-duplicate" },
    why: "duplicate timestamps are rejected, as in the certificate flow",
  },
  "p384-extra-entry-without-proof": {
    expected: { result: "reject", code: "inclusion-proof-missing" },
    why: "every entry from a trusted log is verified, and v0.2+ entries need an inclusion proof",
  },
  "p384-rekor2-integrated-time-zero-number": {
    expected: { result: "reject", code: "bundle-malformed" },
    why: "int64 fields must be JSON strings, as in the certificate flow",
  },
  "p384-rekor2-integrated-time-null": {
    expected: { result: "accept" },
    why: "a null integratedTime is read as absent, as in the certificate flow",
  },
  "p384-rekor2-inclusion-promise-added": {
    expected: { result: "reject", code: "bundle-malformed" },
    why: "an inclusion promise without an integratedTime is malformed, as in the certificate flow",
  },
  "p384-media-type-missing": {
    expected: { result: "reject", code: "media-type-unsupported" },
    why: "a missing media type is rejected rather than read as v0.1, as in the certificate flow",
  },
  "p384-duplicate-dsse-envelope-key": {
    expected: { result: "reject", code: "dsse-signature-invalid" },
    why: "JSON.parse keeps the last dsseEnvelope (another key's); sigstore-rust keeps the first",
  },
  "p384-conflicting-content": {
    expected: { result: "reject", code: "conflicting-oneof" },
    why: "conflicting oneof variants are always rejected",
  },
};

export function expectedFor(v: ManagedKeyVector, mode: Mode): Expected {
  if (mode === "strict") {
    return STRICT_MODE_DIFFERENCES[v.id]?.expected ?? v.expected.profile;
  }
  return DEFAULT_MODE_DIFFERENCES[v.id]?.expected ?? v.expected.library;
}

// A messageSignature bundle has no DSSE envelope, so verifyDsse must refuse it.
const hasDsseEnvelope = (v: ManagedKeyVector): boolean => Boolean(JSON.parse(v.bundle).dsseEnvelope);

// In "dsse" mode, messageSignature vectors are expected to be refused with content-unsupported;
// the manifest records outcomes for the verifying paths only.
function expectedForHow(v: ManagedKeyVector, mode: Mode, how: How): Expected {
  if (how === "dsse" && !hasDsseEnvelope(v)) {
    return { result: "reject", code: "content-unsupported" };
  }
  return expectedFor(v, mode);
}

async function outcome(fn: () => Promise<unknown>): Promise<Outcome> {
  try {
    await fn();
    return { result: "accept" };
  } catch (e) {
    const err = e as { code?: unknown; message?: unknown };
    const code = typeof err.code === "string" ? err.code : undefined;
    const message = String(err.message ?? e);
    return { result: "reject", code, message };
  }
}

export async function verifyManagedKeyVector(lib: Lib, v: ManagedKeyVector, mode: Mode, how: How): Promise<Outcome> {
  const profile = mode === "strict" ? lib.STRICT_MANAGED_KEY_PROFILE : {};
  const options = { ...profile, verifyDigest: verifySignatureOverDigest };
  const verifier = new lib.ManagedKeyVerifier(options);
  const root = JSON.parse(v.root);
  await verifier.loadTrustedRoot(root);
  return outcome(async () => {
    if (how === "dsse") {
      await verifier.verifyDsse(v.bundle, v.key);
    } else {
      const artifact = base64ToBytes(v.artifact);
      const data = how === "digest" ? await digestForVector(v, artifact) : artifact;
      await verifier.verifyArtifact(v.bundle, v.key, data, how === "digest");
    }
  });
}

function matches(expected: Expected, actual: Outcome): boolean {
  if (expected.result !== actual.result) {
    return false;
  }
  if (expected.result === "accept") {
    return true;
  }
  return expected.code === actual.code;
}

/** Every managed-key vector, plus a check that each negative's parent is accepted in the same mode. */
export async function checkManagedKeyCorpus(
  lib: Lib,
  vectors: ManagedKeyVector[],
  mode: Mode,
  how: How,
): Promise<Mismatch[]> {
  const mismatches: Mismatch[] = [];
  const outcomes = new Map<string, Outcome>();
  const byId = new Map(vectors.map((v) => [v.id, v]));
  for (const v of vectors) {
    const actual = await verifyManagedKeyVector(lib, v, mode, how);
    outcomes.set(v.id, actual);
    const expected = expectedForHow(v, mode, how);
    if (!matches(expected, actual)) mismatches.push({ id: v.id, how: `${mode}/${how}`, expected, actual });
  }
  for (const v of vectors) {
    if (!v.parent) {
      continue;
    }
    // A messageSignature parent cannot be accepted by verifyDsse; skip the parent check there.
    const parent = byId.get(v.parent);
    if (how === "dsse" && parent && !hasDsseEnvelope(parent)) {
      continue;
    }
    if (outcomes.get(v.parent)?.result !== "accept") {
      const actual = outcomes.get(v.parent) ?? { result: "reject" };
      mismatches.push({
        id: `${v.id} (parent ${v.parent})`,
        how: `${mode}/${how}`,
        expected: { result: "accept" },
        actual,
      });
    }
  }
  return mismatches;
}

export type { Corpus };
