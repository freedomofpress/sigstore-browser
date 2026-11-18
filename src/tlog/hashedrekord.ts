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

import { base64ToUint8Array, digest, hexToUint8Array, uint8ArrayEqual } from "@freedomofpress/crypto-browser";

import type { SigstoreBundle } from "../bundle.js";
import { preAuthEncoding } from "../dsse.js";
import { fail } from "../errors.js";
import { getHashAlgorithm } from "../interfaces.js";
import { ManagedPublicKey } from "../key.js";
import { assertLoggedSigner, assertLoggedV2Verifier, type LogSigner, type RekorEntry, type V2Verifier } from "./body.js";

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
      verifier?: V2Verifier;
    };
    data: {
      algorithm: string;
      digest: string;
    };
  };
}

export async function verifyHashedRekordBody(
  entry: RekorEntry,
  bundle: SigstoreBundle,
  signer: LogSigner,
): Promise<void> {
  const hashedRekordEntry = entry as HashedRekordEntry;

  switch (hashedRekordEntry.apiVersion) {
    case "0.0.1":
      return verifyHashedRekordV001Body(hashedRekordEntry, bundle, signer);
    case "0.0.2":
      return verifyHashedRekordV002Body(hashedRekordEntry, bundle, signer);
    default:
      fail("tlog-entry-kind", `Unsupported hashedrekord version: ${hashedRekordEntry.apiVersion}`);
  }
}

function verifyHashedRekordV001Body(
  entry: HashedRekordEntry,
  bundle: SigstoreBundle,
  signer: LogSigner,
): void {
  const spec = entry.spec as HashedRekordSpec;
  if (!bundle.messageSignature) {
    fail("tlog-entry-kind", "Bundle missing messageSignature for hashedrekord entry");
  }
  assertLoggedSigner(signer, spec.signature?.publicKey?.content);

  const tlogSig = spec.signature.content || "";
  const tlogSigBytes = base64ToUint8Array(tlogSig);
  const bundleSigBytes = base64ToUint8Array(bundle.messageSignature.signature);

  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    fail("tlog-signature-mismatch", "Signature mismatch between TLog entry and bundle");
  }

  const tlogDigest = spec.data?.hash?.value || "";
  const tlogDigestBytes = hexToUint8Array(tlogDigest);
  const bundleDigestBytes = base64ToUint8Array(
    bundle.messageSignature.messageDigest.digest
  );

  if (!uint8ArrayEqual(tlogDigestBytes, bundleDigestBytes)) {
    fail("tlog-digest-mismatch", "Digest mismatch between TLog entry and bundle");
  }
}

// New functionality for HashedRekord v0.0.2 (not in sigstore-js reference, which only supports v0.0.1)
// Rekor v2 logs DSSE bundles as hashedrekord too: the entry then holds the envelope signature and the
// hash of the envelope's PAE (same reconstruction as sigstore-go's verify/tlog.go).
async function verifyHashedRekordV002Body(
  entry: HashedRekordEntry,
  bundle: SigstoreBundle,
  signer: LogSigner,
): Promise<void> {
  const spec = (entry.spec as HashedRekordV002Spec).hashedRekordV002;
  assertLoggedV2Verifier(signer, spec?.signature?.verifier);

  // A managed key fixes the digest: its key details name the algorithm, which fixes the length.
  if (signer instanceof ManagedPublicKey) {
    const keyDetails = spec.signature.verifier?.keyDetails;
    const details = ManagedPublicKey.curveForKeyDetails(keyDetails);
    const loggedAlgorithm = spec.data?.algorithm;
    const expectedAlgorithm = details?.digestAlgorithm;
    if (loggedAlgorithm !== expectedAlgorithm) {
      const algorithmName = String(loggedAlgorithm);
      const detailsName = String(keyDetails);
      const message = `digest algorithm ${algorithmName} does not match key details ${detailsName}`;
      fail("tlog-digest-algorithm-mismatch", message);
    }
    const loggedDigest = base64ToUint8Array(spec.data.digest || "");
    const length = loggedDigest.length;
    const expectedLength = details?.digestLength;
    if (length !== expectedLength) {
      const message = `${spec.data.algorithm} digest is ${length} bytes, expected ${expectedLength}`;
      fail("tlog-digest-malformed", message);
    }
  }

  let bundleSigB64: string;
  let bundleDigestBytes: Uint8Array;
  if (bundle.messageSignature) {
    bundleSigB64 = bundle.messageSignature.signature;
    bundleDigestBytes = base64ToUint8Array(bundle.messageSignature.messageDigest.digest);
  } else if (bundle.dsseEnvelope) {
    const env = bundle.dsseEnvelope;
    bundleSigB64 = env.signatures[0].sig;
    const pae = preAuthEncoding(env.payloadType, base64ToUint8Array(env.payload));
    bundleDigestBytes = await digest(getHashAlgorithm(spec.data.algorithm), pae);
  } else {
    fail("content-unsupported", "Bundle missing messageSignature or dsseEnvelope for hashedrekord v0.0.2 entry");
  }

  // NOTE: HashedRekord v0.0.2 uses single base64 encoding (unlike intoto which is double-encoded)
  // Verified against Sigstore conformance test suite bundles
  const tlogSigBytes = base64ToUint8Array(spec.signature.content || "");
  const bundleSigBytes = base64ToUint8Array(bundleSigB64);
  if (!uint8ArrayEqual(tlogSigBytes, bundleSigBytes)) {
    fail("tlog-signature-mismatch", "Signature mismatch between TLog entry and bundle (v0.0.2)");
  }

  const tlogDigestBytes = base64ToUint8Array(spec.data.digest || "");
  if (!uint8ArrayEqual(tlogDigestBytes, bundleDigestBytes)) {
    fail("tlog-digest-mismatch", "Digest mismatch between TLog entry and bundle (v0.0.2)");
  }
}
