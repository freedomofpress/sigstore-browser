/*
 * DSSE transparency log entry verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/tlog/dsse.ts
 * Adds v0.0.2 (Rekor v2) support, which the reference lacks.
 */

import { base64ToUint8Array, hexToUint8Array, uint8ArrayEqual } from "@freedomofpress/crypto-browser";
import { getHashAlgorithm } from "../interfaces.js";
import type { SigstoreBundle } from "../bundle.js";
import type { X509Certificate } from "../x509/cert.js";
import { assertLoggedCertificate, type RekorEntry } from "./body.js";

interface DSSESpec {
  signatures?: Array<{
    signature: string;
    verifier?: string;
  }>;
  payloadHash?: {
    algorithm: string;
    value: string;
  };
}

interface DSSEV002Spec {
  dsseV002?: {
    signatures?: Array<{
      content: string;
      verifier?: { x509Certificate?: { rawBytes: string } };
    }>;
    payloadHash?: {
      algorithm: string;
      digest: string;
    };
  };
}

interface DSSEEntry extends RekorEntry {
  apiVersion: "0.0.1" | "0.0.2";
  kind: "dsse";
  spec: DSSESpec | DSSEV002Spec;
}

export async function verifyDSSEBody(
  entry: RekorEntry,
  bundle: SigstoreBundle,
  cert: X509Certificate,
): Promise<void> {
  const dsseEntry = entry as DSSEEntry;
  if (!bundle.dsseEnvelope) {
    throw new Error("Bundle missing dsseEnvelope for DSSE entry");
  }

  // v0.0.1 stores the payload hash as hex and the certificate as base64 PEM; v0.0.2 uses base64 DER for both.
  let tlogSig: Uint8Array, tlogHash: Uint8Array, algorithm: string | undefined;
  switch (dsseEntry.apiVersion) {
    case "0.0.1": {
      const spec = dsseEntry.spec as DSSESpec;
      if (spec.signatures?.length !== 1) {
        throw new Error("DSSE entry must have exactly one signature");
      }
      tlogSig = base64ToUint8Array(spec.signatures[0].signature || "");
      tlogHash = hexToUint8Array(spec.payloadHash?.value || "");
      algorithm = spec.payloadHash?.algorithm;
      assertLoggedCertificate(cert, spec.signatures[0].verifier, true);
      break;
    }
    case "0.0.2": {
      const spec = (dsseEntry.spec as DSSEV002Spec).dsseV002;
      if (spec?.signatures?.length !== 1) {
        throw new Error("DSSE entry must have exactly one signature");
      }
      tlogSig = base64ToUint8Array(spec.signatures[0].content || "");
      tlogHash = base64ToUint8Array(spec.payloadHash?.digest || "");
      algorithm = spec.payloadHash?.algorithm;
      assertLoggedCertificate(cert, spec.signatures[0].verifier?.x509Certificate?.rawBytes, false);
      break;
    }
    default:
      throw new Error(`Unsupported dsse version: ${dsseEntry.apiVersion}`);
  }

  if (!algorithm) {
    throw new Error("DSSE entry missing payloadHash or algorithm");
  }
  if (!uint8ArrayEqual(tlogSig, base64ToUint8Array(bundle.dsseEnvelope.signatures[0].sig))) {
    throw new Error("DSSE signature mismatch between TLog entry and bundle");
  }
  const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
  const bundleHash = new Uint8Array(
    await crypto.subtle.digest(getHashAlgorithm(algorithm), payloadBytes as BufferSource),
  );
  if (!uint8ArrayEqual(tlogHash, bundleHash)) {
    throw new Error("DSSE payload hash mismatch between TLog entry and bundle");
  }
}
