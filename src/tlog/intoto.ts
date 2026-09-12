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

import type { SigstoreBundle } from "../bundle.js";
import { getHashAlgorithm } from "../interfaces.js";
import type { X509Certificate } from "../x509/cert.js";
import { assertLoggedCertificate, type RekorEntry } from "./body.js";

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
  bundle: SigstoreBundle,
  cert: X509Certificate,
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

  // The intoto entry stores the base64 signature base64-encoded once more, so decode twice.
  const tlogSigBytes = base64ToUint8Array(base64Decode(tlogEnvelope.signatures[0].sig));

  assertLoggedCertificate(cert, tlogEnvelope.signatures[0].publicKey, true);

  const bundleSigBytes = base64ToUint8Array(bundle.dsseEnvelope.signatures[0].sig);

  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    throw new Error("Intoto signature mismatch between TLog entry and bundle");
  }

  // The payload hash is optional in the schema, so only check it when present.
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
