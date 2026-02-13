/*
 * Intoto transparency log entry verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/tlog/intoto.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: uses Uint8Array instead of Buffer for binary data
 * - Direct bundle field comparison instead of SignatureContent abstraction
 * - Uses crypto.subtle.digest for hash computation instead of Node.js crypto
 */

import { base64Decode, base64ToUint8Array, hexToUint8Array, uint8ArrayEqual } from "@freedomofpress/crypto-browser";
import { getHashAlgorithm } from "../interfaces.js";
import type { SigstoreBundle } from "../bundle.js";
import type { RekorEntry } from "./body.js";

interface IntotoEnvelope {
  payload: string;
  payloadType: string;
  signatures: Array<{
    keyid?: string;
    sig: string;
    publicKey?: string;
  }>;
}

interface IntotoSpec {
  content: {
    envelope: IntotoEnvelope;
    hash?: {
      algorithm: string;
      value: string;
    };
    payloadHash?: {
      algorithm: string;
      value: string;
    };
  };
  publicKey?: string;
}

interface IntotoEntry extends RekorEntry {
  apiVersion: "0.0.2";
  kind: "intoto";
  spec: IntotoSpec;
}

export async function verifyIntotoBody(
  entry: RekorEntry,
  bundle: SigstoreBundle
): Promise<void> {
  const intotoEntry = entry as IntotoEntry;

  if (intotoEntry.apiVersion !== "0.0.2") {
    throw new Error(
      `Unsupported intoto version: ${intotoEntry.apiVersion}`
    );
  }

  if (!bundle.dsseEnvelope) {
    throw new Error("Bundle missing dsseEnvelope for intoto entry");
  }

  const tlogEnvelope = intotoEntry.spec.content.envelope;

  if (!tlogEnvelope.signatures || tlogEnvelope.signatures.length !== 1) {
    throw new Error("Intoto entry must have exactly one signature");
  }

  // The signature in the intoto tlog entry is double-base64-encoded:
  // 1. Raw signature bytes are base64-encoded (normal)
  // 2. That base64 string is base64-encoded again (for storage in JSON)
  // So we decode twice: base64 -> string -> base64 -> bytes
  const tlogSigBase64 = tlogEnvelope.signatures[0].sig;
  const tlogSigDecoded = base64Decode(tlogSigBase64); // First decode: base64 -> UTF-8 string (which contains base64)
  const tlogSigBytes = base64ToUint8Array(tlogSigDecoded); // Second decode: base64 string -> raw bytes

  if (bundle.dsseEnvelope.signatures.length === 0) {
    throw new Error("Bundle DSSE envelope missing signatures");
  }

  const bundleSigBytes = base64ToUint8Array(bundle.dsseEnvelope.signatures[0].sig);

  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    throw new Error("Intoto signature mismatch between TLog entry and bundle");
  }

  if (intotoEntry.spec.content.payloadHash) {
    if (!intotoEntry.spec.content.payloadHash.algorithm) {
      throw new Error("Intoto entry missing payloadHash algorithm");
    }

    const hashAlg = getHashAlgorithm(intotoEntry.spec.content.payloadHash.algorithm);
    const tlogHashBytes = hexToUint8Array(intotoEntry.spec.content.payloadHash.value);

    const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
    const bundleHashBytes = new Uint8Array(
      await crypto.subtle.digest(hashAlg, payloadBytes as BufferSource)
    );

    if (!uint8ArrayEqual(tlogHashBytes, bundleHashBytes)) {
      throw new Error("Intoto payload hash mismatch between TLog entry and bundle");
    }
  }
}
