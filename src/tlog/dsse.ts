/*
 * DSSE transparency log entry verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/tlog/dsse.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: uses Uint8Array instead of Buffer for binary data
 * - Direct bundle field comparison instead of SignatureContent abstraction
 * - Uses crypto.subtle.digest for hash computation instead of Node.js crypto
 * - Adds verifyDSSE002Body() - new functionality (reference only supports v0.0.1)
 */

import { base64ToUint8Array, hexToUint8Array, toArrayBuffer, uint8ArrayEqual } from "../encoding.js";
import type { SigstoreBundle } from "../bundle.js";
import type { RekorEntry } from "./body.js";

interface DSSESpec {
  signatures?: Array<{
    signature: string;
    verifier?: string;
    keyid?: string;
  }>;
  payloadHash?: {
    algorithm: string;
    value: string;
  };
  envelopeHash?: {
    algorithm: string;
    value: string;
  };
}

interface DSSEEntry extends RekorEntry {
  apiVersion: "0.0.1" | "0.0.2";
  kind: "dsse";
  spec: DSSESpec;
}

export async function verifyDSSEBody(
  entry: RekorEntry,
  bundle: SigstoreBundle
): Promise<void> {
  const dsseEntry = entry as DSSEEntry;

  switch (dsseEntry.apiVersion) {
    case "0.0.1":
      return verifyDSSE001Body(dsseEntry, bundle);
    case "0.0.2":
      return verifyDSSE002Body(dsseEntry, bundle);
    default:
      throw new Error(
        `Unsupported dsse version: ${dsseEntry.apiVersion}`
      );
  }
}

async function verifyDSSE001Body(
  entry: DSSEEntry,
  bundle: SigstoreBundle
): Promise<void> {
  if (!bundle.dsseEnvelope) {
    throw new Error("Bundle missing dsseEnvelope for DSSE entry");
  }

  if (!entry.spec.signatures || entry.spec.signatures.length !== 1) {
    throw new Error("DSSE entry must have exactly one signature");
  }

  const tlogSig = entry.spec.signatures[0].signature;
  const tlogSigBytes = base64ToUint8Array(tlogSig);

  if (bundle.dsseEnvelope.signatures.length === 0) {
    throw new Error("Bundle DSSE envelope missing signatures");
  }

  const bundleSigBytes = base64ToUint8Array(bundle.dsseEnvelope.signatures[0].sig);

  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    throw new Error("DSSE signature mismatch between TLog entry and bundle");
  }

  const tlogHash = entry.spec.payloadHash?.value || "";
  if (!tlogHash) {
    throw new Error("DSSE entry missing payloadHash");
  }

  const tlogHashBytes = hexToUint8Array(tlogHash);

  const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
  const bundleHashBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(payloadBytes))
  );

  if (!uint8ArrayEqual(tlogHashBytes, bundleHashBytes)) {
    throw new Error("DSSE payload hash mismatch between TLog entry and bundle");
  }
}

// New functionality for DSSE v0.0.2 (not in sigstore-js reference, which only supports v0.0.1)
async function verifyDSSE002Body(
  entry: DSSEEntry,
  bundle: SigstoreBundle
): Promise<void> {
  if (!bundle.dsseEnvelope) {
    throw new Error("Bundle missing dsseEnvelope for DSSE v0.0.2 entry");
  }

  const spec = (entry.spec as any).dsseV002;
  if (!spec) {
    throw new Error("DSSE v0.0.2 entry missing dsseV002 spec");
  }

  if (!spec.signatures || spec.signatures.length !== 1) {
    throw new Error("DSSE v0.0.2 entry must have exactly one signature");
  }

  const tlogSig = spec.signatures[0].content;
  const tlogSigBytes = base64ToUint8Array(tlogSig);

  if (bundle.dsseEnvelope.signatures.length === 0) {
    throw new Error("Bundle DSSE envelope missing signatures");
  }

  const bundleSigBytes = base64ToUint8Array(bundle.dsseEnvelope.signatures[0].sig);

  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    throw new Error("DSSE signature mismatch between TLog entry and bundle (v0.0.2)");
  }

  const tlogHash = spec.payloadHash?.digest || "";
  if (!tlogHash) {
    throw new Error("DSSE v0.0.2 entry missing payloadHash");
  }

  const tlogHashBytes = base64ToUint8Array(tlogHash);

  const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
  const bundleHashBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(payloadBytes))
  );

  if (!uint8ArrayEqual(tlogHashBytes, bundleHashBytes)) {
    throw new Error("DSSE payload hash mismatch between TLog entry and bundle (v0.0.2)");
  }
}
