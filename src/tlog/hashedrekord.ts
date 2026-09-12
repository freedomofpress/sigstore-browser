/*
 * HashedRekord transparency log entry verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/tlog/hashedrekord.ts
 * Adds v0.0.2 (Rekor v2) support, which the reference lacks.
 */

import { base64ToUint8Array, hexToUint8Array, uint8ArrayEqual } from "@freedomofpress/crypto-browser";
import type { SigstoreBundle } from "../bundle.js";
import type { X509Certificate } from "../x509/cert.js";
import { assertLoggedCertificate, type RekorEntry } from "./body.js";

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

interface HashedRekordEntry extends RekorEntry {
  apiVersion: "0.0.1" | "0.0.2";
  kind: "hashedrekord";
  spec: HashedRekordSpec | HashedRekordV002Spec;
}

export function verifyHashedRekordBody(
  entry: RekorEntry,
  bundle: SigstoreBundle,
  cert: X509Certificate,
): void {
  const hashedRekordEntry = entry as HashedRekordEntry;
  if (!bundle.messageSignature) {
    throw new Error("Bundle missing messageSignature for hashedrekord entry");
  }
  const bundleSig = base64ToUint8Array(bundle.messageSignature.signature);
  const bundleDigest = base64ToUint8Array(bundle.messageSignature.messageDigest.digest);

  // v0.0.1 stores the digest as hex and the certificate as base64 PEM; v0.0.2 uses base64 DER for both.
  let tlogSig: Uint8Array, tlogDigest: Uint8Array;
  switch (hashedRekordEntry.apiVersion) {
    case "0.0.1": {
      const spec = hashedRekordEntry.spec as HashedRekordSpec;
      tlogSig = base64ToUint8Array(spec.signature?.content || "");
      tlogDigest = hexToUint8Array(spec.data?.hash?.value || "");
      assertLoggedCertificate(cert, spec.signature?.publicKey?.content, true);
      break;
    }
    case "0.0.2": {
      const spec = (hashedRekordEntry.spec as HashedRekordV002Spec).hashedRekordV002;
      tlogSig = base64ToUint8Array(spec?.signature?.content || "");
      tlogDigest = base64ToUint8Array(spec?.data?.digest || "");
      assertLoggedCertificate(cert, spec?.signature?.verifier?.x509Certificate?.rawBytes, false);
      break;
    }
    default:
      throw new Error(`Unsupported hashedrekord version: ${hashedRekordEntry.apiVersion}`);
  }

  if (!uint8ArrayEqual(tlogSig, bundleSig)) {
    throw new Error("Signature mismatch between TLog entry and bundle");
  }
  if (!uint8ArrayEqual(tlogDigest, bundleDigest)) {
    throw new Error("Digest mismatch between TLog entry and bundle");
  }
}
