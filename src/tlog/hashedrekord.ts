/*
 * HashedRekord transparency log entry verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/tlog/hashedrekord.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: uses Uint8Array instead of Buffer for binary data
 * - Direct bundle field comparison instead of SignatureContent abstraction
 * - Adds verifyHashedRekordV002Body() - new functionality (reference only supports v0.0.1)
 */

import { base64ToUint8Array, hexToUint8Array, uint8ArrayEqual } from "../encoding.js";
import type { SigstoreBundle } from "../bundle.js";
import type { RekorEntry } from "./body.js";

interface HashedRekordSpec {
  signature: {
    content: string;
    publicKey: {
      content: string;
    };
  };
  data: {
    hash: {
      algorithm: string;
      value: string;
    };
  };
}

interface HashedRekordEntry extends RekorEntry {
  apiVersion: "0.0.1" | "0.0.2";
  kind: "hashedrekord";
  spec: HashedRekordSpec | HashedRekordV002Spec;
}

interface HashedRekordV002Spec {
  hashedRekordV002: {
    signature: {
      content: string;
      verifier: {
        x509Certificate: {
          rawBytes: string;
        };
      };
    };
    data: {
      algorithm: string;
      digest: string;
    };
  };
}

export async function verifyHashedRekordBody(
  entry: RekorEntry,
  bundle: SigstoreBundle
): Promise<void> {
  const hashedRekordEntry = entry as HashedRekordEntry;

  switch (hashedRekordEntry.apiVersion) {
    case "0.0.1":
      return verifyHashedRekordV001Body(hashedRekordEntry, bundle);
    case "0.0.2":
      return verifyHashedRekordV002Body(hashedRekordEntry, bundle);
    default:
      throw new Error(
        `Unsupported hashedrekord version: ${hashedRekordEntry.apiVersion}`
      );
  }
}

function verifyHashedRekordV001Body(
  entry: HashedRekordEntry,
  bundle: SigstoreBundle
): void {
  const spec = entry.spec as HashedRekordSpec;
  if (!bundle.messageSignature) {
    throw new Error("Bundle missing messageSignature for hashedrekord entry");
  }

  const tlogSig = spec.signature.content || "";
  const tlogSigBytes = base64ToUint8Array(tlogSig);
  const bundleSigBytes = base64ToUint8Array(bundle.messageSignature.signature);

  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    throw new Error("Signature mismatch between TLog entry and bundle");
  }

  const tlogDigest = spec.data.hash?.value || "";
  const tlogDigestBytes = hexToUint8Array(tlogDigest);
  const bundleDigestBytes = base64ToUint8Array(
    bundle.messageSignature.messageDigest.digest
  );

  if (!uint8ArrayEqual(tlogDigestBytes, bundleDigestBytes)) {
    throw new Error("Digest mismatch between TLog entry and bundle");
  }
}

// New functionality for HashedRekord v0.0.2 (not in sigstore-js reference, which only supports v0.0.1)
function verifyHashedRekordV002Body(
  entry: HashedRekordEntry,
  bundle: SigstoreBundle
): void {
  const spec = (entry.spec as HashedRekordV002Spec).hashedRekordV002;
  if (!bundle.messageSignature) {
    throw new Error("Bundle missing messageSignature for hashedrekord v0.0.2 entry");
  }

  // NOTE: HashedRekord v0.0.2 uses single base64 encoding (unlike intoto which is double-encoded)
  // Verified against Sigstore conformance test suite bundles
  const tlogSig = spec.signature.content || "";
  const tlogSigBytes = base64ToUint8Array(tlogSig);
  const bundleSigBytes = base64ToUint8Array(bundle.messageSignature.signature);

  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    throw new Error("Signature mismatch between TLog entry and bundle (v0.0.2)");
  }

  const tlogDigest = spec.data.digest || "";
  const tlogDigestBytes = base64ToUint8Array(tlogDigest);
  const bundleDigestBytes = base64ToUint8Array(
    bundle.messageSignature.messageDigest.digest
  );

  if (!uint8ArrayEqual(tlogDigestBytes, bundleDigestBytes)) {
    throw new Error("Digest mismatch between TLog entry and bundle (v0.0.2)");
  }
}
