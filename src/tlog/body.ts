/*
 * Transparency log body verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/tlog/index.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: uses Uint8Array instead of Buffer for binary data
 * - Direct bundle comparison instead of SignatureContent abstraction
 */

import { base64Decode } from "../encoding.js";
import type { SigstoreBundle, TLogEntry } from "../bundle.js";
import { verifyHashedRekordBody } from "./hashedrekord.js";
import { verifyDSSEBody } from "./dsse.js";
import { verifyIntotoBody } from "./intoto.js";

export interface RekorEntry {
  apiVersion: string;
  kind: string;
  spec: unknown;
}

export async function verifyTLogBody(
  entry: TLogEntry,
  bundle: SigstoreBundle
): Promise<void> {
  const rekorEntry = parseCanonicalBody(entry);

  const { kind, version } = entry.kindVersion;

  if (kind !== rekorEntry.kind || version !== rekorEntry.apiVersion) {
    throw new Error(
      `kind/version mismatch - expected: ${kind}/${version}, received: ${rekorEntry.kind}/${rekorEntry.apiVersion}`
    );
  }

  switch (rekorEntry.kind) {
    case "hashedrekord":
      return verifyHashedRekordBody(rekorEntry, bundle);
    case "dsse":
      return verifyDSSEBody(rekorEntry, bundle);
    case "intoto":
      return verifyIntotoBody(rekorEntry, bundle);
    default:
      throw new Error(`Unsupported TLog entry kind: ${rekorEntry.kind}`);
  }
}

function parseCanonicalBody(entry: TLogEntry): RekorEntry {
  try {
    const decodedBody = base64Decode(entry.canonicalizedBody);
    const rekorEntry = JSON.parse(decodedBody) as RekorEntry;

    if (!rekorEntry.apiVersion || !rekorEntry.kind || !rekorEntry.spec) {
      throw new Error("Invalid Rekor entry structure");
    }

    return rekorEntry;
  } catch (error) {
    throw new Error(
      `Failed to parse canonicalized body: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}
