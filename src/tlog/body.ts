/*
 * Transparency log body verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/tlog/index.ts
 */

import { base64Decode, base64ToUint8Array, Uint8ArrayToString } from "@freedomofpress/crypto-browser";
import type { SigstoreBundle, TLogEntry } from "../bundle.js";
import { X509Certificate } from "../x509/cert.js";
import { verifyHashedRekordBody } from "./hashedrekord.js";
import { verifyDSSEBody } from "./dsse.js";
import { verifyIntotoBody } from "./intoto.js";

export interface RekorEntry {
  apiVersion: string;
  kind: string;
  spec: unknown;
}

// Checks that the entry body matches the bundle content and was logged under the signing certificate.
export async function verifyTLogBody(
  entry: TLogEntry,
  bundle: SigstoreBundle,
  cert: X509Certificate,
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
      return verifyHashedRekordBody(rekorEntry, bundle, cert);
    case "dsse":
      return verifyDSSEBody(rekorEntry, bundle, cert);
    case "intoto":
      return verifyIntotoBody(rekorEntry, bundle, cert);
    default:
      throw new Error(`Unsupported TLog entry kind: ${rekorEntry.kind}`);
  }
}

// Compares the certificate recorded in the entry (base64 DER, or base64 PEM for Rekor v1) with the signing certificate.
export function assertLoggedCertificate(
  cert: X509Certificate,
  encoded: unknown,
  pem: boolean,
): void {
  if (typeof encoded !== "string" || encoded === "") {
    throw new Error("TLog entry does not record the signing certificate");
  }
  const bytes = base64ToUint8Array(encoded);
  const logged = X509Certificate.parse(pem ? Uint8ArrayToString(bytes) : bytes);
  if (!cert.equals(logged)) {
    throw new Error("Certificate in TLog entry does not match the signing certificate");
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
