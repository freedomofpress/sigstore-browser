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

import { base64Decode, base64ToUint8Array, toDER, Uint8ArrayToString } from "@freedomofpress/crypto-browser";

import type { SigstoreBundle, TLogEntry } from "../bundle.js";
import { errorMessage, fail } from "../errors.js";
import { ManagedPublicKey } from "../key.js";
import { X509Certificate } from "../x509/cert.js";
import { verifyDSSEBody } from "./dsse.js";
import { verifyHashedRekordBody } from "./hashedrekord.js";
import { verifyIntotoBody } from "./intoto.js";

export interface RekorEntry {
  apiVersion: string;
  kind: string;
  spec: unknown;
}

// Who signed the bundle: a certificate, or a managed key supplied by the caller.
export type LogSigner = X509Certificate | ManagedPublicKey;

// Checks that the entry body matches the bundle content and was logged under the signing certificate or key.
export async function verifyTLogBody(
  entry: TLogEntry,
  bundle: SigstoreBundle,
  signer: LogSigner,
): Promise<void> {
  const rekorEntry = parseCanonicalBody(entry);

  const { kind, version } = entry.kindVersion;

  if (kind !== rekorEntry.kind || version !== rekorEntry.apiVersion) {
    const expected = `${kind}/${version}`;
    const received = `${rekorEntry.kind}/${rekorEntry.apiVersion}`;
    fail("tlog-entry-malformed", `kind/version mismatch - expected: ${expected}, received: ${received}`);
  }

  switch (rekorEntry.kind) {
    case "hashedrekord":
      return verifyHashedRekordBody(rekorEntry, bundle, signer);
    case "dsse":
      return verifyDSSEBody(rekorEntry, bundle, signer);
    case "intoto":
      return verifyIntotoBody(rekorEntry, bundle, signer);
    default:
      fail("tlog-entry-kind", `Unsupported TLog entry kind: ${rekorEntry.kind}`);
  }
}

// Compares the signer recorded in a Rekor v1 entry (base64 of a PEM certificate or public key) with the signer.
export function assertLoggedSigner(signer: LogSigner, encoded: unknown): void {
  if (signer instanceof X509Certificate) {
    return assertLoggedCertificate(signer, encoded, true);
  }
  if (typeof encoded !== "string" || encoded === "") {
    fail("tlog-key-mismatch", "TLog entry does not record the public key");
  }
  let logged: Uint8Array;
  try {
    const bytes = base64ToUint8Array(encoded);
    const pem = Uint8ArrayToString(bytes);
    logged = toDER(pem);
  } catch {
    fail("tlog-entry-malformed", "TLog entry public key is not valid PEM");
  }
  if (!signer.equals(logged)) {
    fail("tlog-key-mismatch", "Public key in TLog entry does not match the verification key");
  }
}

// Rekor v2 entries record their verifier as an x509Certificate or a publicKey with keyDetails.
export interface V2Verifier {
  x509Certificate?: { rawBytes?: string };
  publicKey?: { rawBytes?: string };
  keyDetails?: string;
}

/**
 * Compares the verifier recorded in a Rekor v2 entry with the signer. For a managed key, the
 * recorded key details must name the curve of the recorded key, which must be the signer's key.
 */
export function assertLoggedV2Verifier(signer: LogSigner, verifier: V2Verifier | undefined): void {
  if (signer instanceof X509Certificate) {
    return assertLoggedCertificate(signer, verifier?.x509Certificate?.rawBytes, false);
  }
  const rawBytes = verifier?.publicKey?.rawBytes;
  const recordsPublicKey = verifier?.x509Certificate === undefined && typeof rawBytes === "string" && rawBytes !== "";
  if (!recordsPublicKey) {
    fail("tlog-key-mismatch", "TLog entry does not record a public key");
  }
  const logged = base64ToUint8Array(rawBytes);
  const details = ManagedPublicKey.curveForKeyDetails(verifier?.keyDetails);
  const curve = ManagedPublicKey.curveOf(logged);
  if (!details || details.namedCurve !== curve) {
    const keyDetails = String(verifier?.keyDetails);
    const curveName = curve ?? "unsupported";
    const message = `key details ${keyDetails} do not match the logged ${curveName} key`;
    fail("tlog-key-details-mismatch", message);
  }
  if (!signer.equals(logged)) {
    fail("tlog-key-mismatch", "Public key in TLog entry does not match the verification key");
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
    const message = errorMessage(error);
    fail("tlog-entry-malformed", `Failed to parse canonicalized body: ${message}`);
  }
}
