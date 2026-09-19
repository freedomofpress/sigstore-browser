import {
  base64ToUint8Array,
  ByteStream,
  canonicalize,
  importKey,
  stringToUint8Array,
  uint8ArrayEqual,
  Uint8ArrayToHex,
  Uint8ArrayToString,
  verifySignature,
  verifySignatureOverDigest,
} from "@freedomofpress/crypto-browser";
import { HashAlgorithms } from "./interfaces.js";
import {
  CertificateChainVerifier,
  EXTENSION_OID_SCT,
  X509Certificate,
  X509SCTExtension,
} from "./x509/index.js";
import { assertBundle, SigstoreBundle, TLogEntry } from "./bundle.js";
import { preAuthEncoding } from "./dsse.js";
import {
  CertAuthority,
  CTLog,
  parseValidityPeriod,
  RawCAs,
  RawLogs,
  RekorKeyInfo,
  Sigstore,
  SigstoreRoots,
  TrustedRoot,
} from "./interfaces.js";
import { verifyMerkleInclusion } from "./tlog/merkle.js";
import { verifyCheckpoint } from "./tlog/checkpoint.js";
import { verifyTLogBody } from "./tlog/body.js";
import { verifyBundleTimestamp } from "./timestamp/tsa.js";
import { TrustedRootProvider } from "./trust/tuf.js";
import type { VerificationPolicy } from "./policy.js";
import { AnyOf, AllOf, OIDCIssuer, OIDCIssuerV2, Identity } from "./policy.js";

const MEDIA_TYPE_BASE = "application/vnd.dev.sigstore.bundle";
// Upper bounds on in-toto subjects and digests, matching sigstore-go.
const MAX_SUBJECTS = 1024;
const MAX_SUBJECT_DIGESTS = 32;

// Unknown operators can satisfy threshold one, but add no independence to named operators.
function countOperators(operators: Set<string>): number {
  if (operators.size === 0) return 0;
  return Math.max(1, operators.size - (operators.has("") ? 1 : 0));
}

/**
 * Extract bundle version from mediaType string
 * Reference: https://github.com/sigstore/sigstore-go/blob/main/pkg/bundle/bundle.go#L159-L177
 */
function getBundleVersion(mediaType: string): string {
  switch (mediaType) {
    case `${MEDIA_TYPE_BASE}+json;version=0.1`:
      return "0.1";
    case `${MEDIA_TYPE_BASE}+json;version=0.2`:
      return "0.2";
    case `${MEDIA_TYPE_BASE}+json;version=0.3`:
      return "0.3";
  }

  // New format: "application/vnd.dev.sigstore.bundle.v0.3+json"
  if (mediaType.startsWith(`${MEDIA_TYPE_BASE}.v`) && mediaType.endsWith("+json")) {
    const version = mediaType
      .replace(`${MEDIA_TYPE_BASE}.v`, "")
      .replace("+json", "");
    // Only the versions this verifier implements are accepted.
    if (/^0\.[123]$/.test(version)) {
      return version;
    }
  }

  throw new Error(`Unsupported bundle media type: ${mediaType}`);
}

export interface SigstoreVerifierOptions {
  tlogThreshold?: number;
  ctlogThreshold?: number;
  tsaThreshold?: number;
}

export class SigstoreVerifier {
  private root: Sigstore | undefined;
  private rawRoot: TrustedRoot | undefined;
  private options: Required<SigstoreVerifierOptions>;

  constructor(options: SigstoreVerifierOptions = {}) {
    this.root = undefined;
    this.rawRoot = undefined;
    this.options = {
      tlogThreshold: options.tlogThreshold ?? 1,
      ctlogThreshold: options.ctlogThreshold ?? 1,
      tsaThreshold: options.tsaThreshold ?? 0,
    };
    for (const [name, threshold] of Object.entries(this.options)) {
      if (!Number.isSafeInteger(threshold) || threshold < 0) {
        throw new Error(`${name} must be a non-negative safe integer`);
      }
    }
  }

  // Loads every Rekor key; entries select theirs by log ID and SETs are checked against its validity window.
  async loadLog(logs: RawLogs): Promise<RekorKeyInfo[]> {
    return Promise.all(
      logs.map(async (log) => ({
        publicKey: await importKey(
          log.publicKey.keyDetails,
          log.publicKey.keyDetails,
          log.publicKey.rawBytes,
        ),
        logId: base64ToUint8Array(log.logId.keyId),
        hashAlgorithm: log.hashAlgorithm,
        // Empty means unknown; countOperators never adds it to the named operator count.
        operator: log.operator || "",
        validFor: parseValidityPeriod(log.publicKey.validFor),
      })),
    );
  }

  // Loads every CT log; SCTs select their log by ID and are checked against its validity window.
  async loadCTLogs(ctlogs: RawLogs): Promise<CTLog[]> {
    if (ctlogs.length === 0) {
      throw new Error("Could not find any CT logs in sigstore root.");
    }
    return Promise.all(
      ctlogs.map(async (log) => ({
        logID: base64ToUint8Array(log.logId.keyId),
        publicKey: await importKey(
          log.publicKey.keyDetails,
          log.publicKey.keyDetails,
          log.publicKey.rawBytes,
        ),
        operator: log.operator || "",
        validFor: parseValidityPeriod(log.publicKey.validFor),
      })),
    );
  }

  // Adapted from https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/key/certificate.ts#L22-L53
  // Verifies that the leaf certificate chains to a trusted CA and is valid at the given timestamp.
  // Differences from sigstore-js:
  // - This is async (uses await) because our CertificateChainVerifier.verify() is async
  // - sigstore-js filters CAs using filterCertAuthorities() before calling this function,
  //   we do the timestamp filtering inline within this function
  async verifyCertificateChain(
    timestamp: Date,
    leaf: X509Certificate,
    certificateAuthorities: CertAuthority[]
  ): Promise<X509Certificate[]> {
    let lastError: any;

    for (const ca of certificateAuthorities) {
      // Check if this CA is valid for the given timestamp
      if (timestamp < ca.validFor.start || timestamp > ca.validFor.end) {
        continue;
      }

      try {
        const verifier = new CertificateChainVerifier({
          trustedCerts: ca.certChain,
          untrustedCert: leaf,
          timestamp,
        });
        return await verifier.verify();
      } catch (err) {
        lastError = err;
      }
    }

    throw new Error(`Failed to verify certificate chain: ${lastError?.message || 'No valid CAs found'}`);
  }

  // Loads every Fulcio CA; verifyCertificateChain() selects CAs by the observer timestamp.
  loadCA(cas: RawCAs): CertAuthority[] {
    return cas
      .filter((ca) => ca.certChain.certificates.length > 0)
      .map((ca) => ({
        certChain: ca.certChain.certificates.map((cert) =>
          X509Certificate.parse(base64ToUint8Array(cert.rawBytes)),
        ),
        validFor: parseValidityPeriod(ca.validFor),
      }));
  }

  async loadSigstoreRoot(rawRoot: TrustedRoot) {
    rawRoot.timestampAuthorities?.forEach((authority) =>
      parseValidityPeriod(authority.validFor),
    );
    const root = {
      rekor: await this.loadLog(rawRoot[SigstoreRoots.tlogs]),
      ctlogs: await this.loadCTLogs(rawRoot[SigstoreRoots.ctlogs]),
      certificateAuthorities: this.loadCA(rawRoot[SigstoreRoots.certificateAuthorities]),
    };
    this.rawRoot = rawRoot;
    this.root = root;
  }

  /**
   * Load Sigstore trusted root via TUF
   * Uses The Update Framework for secure, verified updates of trusted root metadata
   *
   * @param tufProvider Optional TrustedRootProvider instance. If not provided, uses default Sigstore TUF repository
   */
  async loadSigstoreRootWithTUF(tufProvider?: TrustedRootProvider): Promise<void> {
    const provider = tufProvider || new TrustedRootProvider();
    const trustedRoot = await provider.getTrustedRoot();
    await this.loadSigstoreRoot(trustedRoot);
  }

  // Adapted from https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/key/sct.ts
  // Key differences:
  // - Adds duplicate SCT detection (not in reference)
  // - Inline CT log filtering by logID and validity period (reference uses filterTLogAuthorities)
  // - Returns the distinct operators of the logs whose SCTs verified, for threshold checking
  async verifySCT(
    cert: X509Certificate,
    issuer: X509Certificate,
    ctlogs: CTLog[],
  ): Promise<Set<string>> {
    let extSCT: X509SCTExtension | undefined;

    // Verifying the SCT requires that we remove the SCT extension and
    // re-encode the TBS structure to DER -- this value is part of the data
    // over which the signature is calculated. Since this is a destructive action
    // we create a copy of the certificate so we can remove the SCT extension
    // without affecting the original certificate.
    const clone = cert.clone();

    // Intentionally not using the findExtension method here because we want to
    // remove the the SCT extension from the certificate before calculating the
    // PreCert structure
    for (let i = 0; i < clone.extensions.length; i++) {
      const ext = clone.extensions[i];

      if (ext.subs[0].toOID() === EXTENSION_OID_SCT) {
        extSCT = new X509SCTExtension(ext);

        // Remove the extension from the certificate
        clone.extensions.splice(i, 1);
        break;
      }
    }

    // No SCT extension found - fail verification
    if (!extSCT) {
      throw new Error("Certificate is missing required SCT extension");
    }

    // Found an SCT extension but it has no SCTs - fail verification
    if (extSCT.signedCertificateTimestamps.length === 0) {
      throw new Error("SCT extension is present but contains no SCTs");
    }

    // Check for duplicate SCTs (same log ID)
    const seenLogIds = new Set<string>();
    for (const sct of extSCT.signedCertificateTimestamps) {
      const logIdHex = Uint8ArrayToHex(sct.logID);
      if (seenLogIds.has(logIdHex)) {
        throw new Error(`Duplicate SCT found for log ID: ${logIdHex}`);
      }
      seenLogIds.add(logIdHex);
    }

    // Construct the PreCert structure
    // https://www.rfc-editor.org/rfc/rfc6962#section-3.2
    const preCert = new ByteStream();

    // Calculate hash of the issuer's public key
    const issuerId = new Uint8Array(
      await crypto.subtle.digest(HashAlgorithms.SHA256, issuer.publicKey as BufferSource),
    );
    preCert.appendView(issuerId);

    // Re-encodes the certificate to DER after removing the SCT extension
    const tbs = clone.tbsCertificate.toDER();
    preCert.appendUint24(tbs.length);
    preCert.appendView(tbs);

    // Calculate and return the verification results for each SCT
    // Unlike sigstore-go which counts verified SCTs and checks threshold at the end,
    // sigstore-js throws immediately if any SCT fails verification
    const operators = new Set<string>();

    for (const sct of extSCT.signedCertificateTimestamps) {
      // Find the CT log that matches this SCT's log ID and is valid for the SCT datetime
      const validCTLogs = ctlogs.filter((log) => {
        // Check if log IDs match
        if (!uint8ArrayEqual(log.logID, sct.logID)) return false;
        // Check that the SCT datetime is within the log's validity period
        return log.validFor.start <= sct.datetime && sct.datetime <= log.validFor.end;
      });

      // See if the SCT is valid for any of the CT logs
      const verified = await (async () => {
        for (const log of validCTLogs) {
          try {
            if (await sct.verify(preCert.buffer, log.publicKey)) {
              return log;
            }
          } catch {
            // Continue trying other logs
          }
        }
        return undefined;
      })();

      if (!verified) {
        throw new Error("SCT verification failed");
      }

      operators.add(verified.operator);
    }

    return operators;
  }

  // Verifies the signed entry timestamp and returns the integrated time it binds.
  private async verifySET(entry: TLogEntry, promise: string, log: RekorKeyInfo): Promise<Date> {
    const integratedTime = Number(entry.integratedTime);
    const integratedDate = new Date(integratedTime * 1000);
    if (integratedDate < log.validFor.start || integratedDate > log.validFor.end) {
      throw new Error("Rekor key was not valid at the integrated time.");
    }
    const signed = stringToUint8Array(
      canonicalize({
        body: entry.canonicalizedBody,
        integratedTime,
        logIndex: Number(entry.logIndex),
        logID: Uint8ArrayToHex(log.logId),
      }),
    );
    if (!(await verifySignature(log.publicKey, signed, base64ToUint8Array(promise), log.hashAlgorithm))) {
      throw new Error("Failed to verify the inclusion promise in the provided bundle.");
    }
    return integratedDate;
  }

  // Fully verifies every entry from a trusted log and returns the SET-bound integrated times.
  // Entries from unknown logs are ignored; the threshold counts distinct log operators that verified.
  private async verifyTlogEntries(
    cert: X509Certificate,
    bundle: SigstoreBundle,
    rekor: RekorKeyInfo[],
  ): Promise<Date[]> {
    const entries = bundle.verificationMaterial.tlogEntries;
    // Only v0.1 bundles may rely on an inclusion promise alone.
    const requireProof = getBundleVersion(bundle.mediaType) !== "0.1";
    const operators = new Set<string>();
    const integratedTimes: Date[] = [];

    for (const entry of entries) {
      const logId = base64ToUint8Array(entry.logId.keyId);
      const log = rekor.find((l) => uint8ArrayEqual(l.logId, logId));
      if (!log) continue;

      const promise = entry.inclusionPromise?.signedEntryTimestamp;
      if (!entry.inclusionProof && (requireProof || !promise)) {
        throw new Error("Transparency log entry requires an inclusion proof.");
      }
      if (promise) {
        integratedTimes.push(await this.verifySET(entry, promise, log));
      }
      if (entry.inclusionProof) {
        await verifyMerkleInclusion(entry);
        await verifyCheckpoint(entry, log);
      }
      if (entry.integratedTime && !cert.validForDate(new Date(Number(entry.integratedTime) * 1000))) {
        throw new Error("Artifact signing was logged outside of the certificate validity.");
      }
      await verifyTLogBody(entry, bundle, cert);
      operators.add(log.operator);
    }

    const verifiedOperators = countOperators(operators);
    if (verifiedOperators < this.options.tlogThreshold) {
      throw new Error(`Not enough verified transparency logs: ${verifiedOperators} < ${this.options.tlogThreshold}`);
    }
    return integratedTimes;
  }

  // Shared checks: policy, transparency log, timestamps, chain at every observer time, SCTs.
  // Returns the signing certificate and the bundle's signature.
  private async verifyBundle(
    bundle: SigstoreBundle,
    policy: VerificationPolicy,
  ): Promise<{ signingCert: X509Certificate; signature: Uint8Array }> {
    assertBundle(bundle);
    if (!this.root || !this.rawRoot) {
      throw new Error("Sigstore root is undefined");
    }

    const cert = bundle.verificationMaterial.certificate ||
      bundle.verificationMaterial.x509CertificateChain?.certificates[0];
    if (!cert) {
      throw new Error("No certificate found in bundle");
    }
    const signingCert = X509Certificate.parse(base64ToUint8Array(cert.rawBytes));
    const signature = base64ToUint8Array(
      bundle.messageSignature ? bundle.messageSignature.signature : bundle.dsseEnvelope.signatures[0].sig,
    );

    await policy.verify(signingCert);

    // Observer timestamps come from SET-bound integrated times and verified RFC 3161 timestamps.
    // Rekor v2 entries carry no integrated time, so they need a TSA timestamp to be anchored at all.
    const integratedTimes = await this.verifyTlogEntries(signingCert, bundle, this.root.rekor);
    const timestamps = await verifyBundleTimestamp(
      bundle.verificationMaterial.timestampVerificationData,
      signature,
      this.rawRoot.timestampAuthorities || [],
    );
    const tsaOperators = countOperators(new Set(timestamps.map((t) => t.operator)));
    if (tsaOperators < this.options.tsaThreshold) {
      throw new Error(`Not enough verified TSA operators: ${tsaOperators} < ${this.options.tsaThreshold}`);
    }
    const observerTimes = [...integratedTimes, ...timestamps.map((t) => t.signingTime)];
    if (observerTimes.length === 0) {
      throw new Error("No verified observer timestamp anchors the signature in time.");
    }

    // The CA window and the whole chain are checked at every observer time, never at the leaf's own notBefore.
    let certPath: X509Certificate[] = [];
    for (const ts of observerTimes) {
      certPath = await this.verifyCertificateChain(ts, signingCert, this.root.certificateAuthorities);
    }
    const issuerCert = certPath.length > 1 ? certPath[1] : certPath[0];
    const ctOperators = countOperators(await this.verifySCT(signingCert, issuerCert, this.root.ctlogs));
    if (ctOperators < this.options.ctlogThreshold) {
      throw new Error(`Not enough verified CT log operators: ${ctOperators} < ${this.options.ctlogThreshold}`);
    }

    return { signingCert, signature };
  }

  public async verifyArtifactPolicy(
    policy: VerificationPolicy,
    bundle: SigstoreBundle,
    data: Uint8Array,
    isDigestOnly: boolean = false,
  ): Promise<boolean> {
    if (isDigestOnly && data.byteLength !== 32) {
      throw new Error("SHA-256 digest must be exactly 32 bytes");
    }
    const { signingCert, signature } = await this.verifyBundle(bundle, policy);

    // # 7 Revocation *skipping* not really a thing (unsurprisingly)

    // # 8 verify the signed data
    if (bundle.dsseEnvelope) {
      // Only in-toto statements are understood; other payload types must not be read as one.
      if (bundle.dsseEnvelope.payloadType !== "application/vnd.in-toto+json") {
        throw new Error(`Unsupported DSSE payload type: ${bundle.dsseEnvelope.payloadType}`);
      }
      const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
      const payload = JSON.parse(Uint8ArrayToString(payloadBytes));

      // Verify the artifact digest matches a subject in the in-toto statement
      if (!Array.isArray(payload?.subject) || payload.subject.length === 0 || payload.subject.length > MAX_SUBJECTS) {
        throw new Error(`DSSE payload must have between 1 and ${MAX_SUBJECTS} subjects`);
      }
      // Compute or extract the artifact digest
      let artifactDigest: string;
      if (isDigestOnly) {
        // data is already the digest bytes
        artifactDigest = Uint8ArrayToHex(data);
      } else {
        // data is the file content, compute the digest
        artifactDigest = Uint8ArrayToHex(
          new Uint8Array(await crypto.subtle.digest(HashAlgorithms.SHA256, data as BufferSource))
        );
      }

      // Every subject must carry a bounded digest map; any one of them may match the artifact.
      let matchedSubject = false;
      for (const subject of payload.subject) {
        const digests = subject?.digest;
        if (!digests || typeof digests !== "object" || Array.isArray(digests) || Object.keys(digests).length > MAX_SUBJECT_DIGESTS) {
          throw new Error(`Invalid DSSE subject digest map (maximum ${MAX_SUBJECT_DIGESTS} digests)`);
        }
        matchedSubject ||= typeof digests.sha256 === "string" && artifactDigest === digests.sha256.toLowerCase();
      }

      if (!matchedSubject) {
        throw new Error(
          `Artifact digest ${artifactDigest} does not match any subject in DSSE payload`
        );
      }

      // Create PAE (Pre-Authentication Encoding) for signature verification
      const pae = preAuthEncoding(bundle.dsseEnvelope.payloadType, payloadBytes);

      const publicKey = await signingCert.publicKeyObj;
      const verified = await verifySignature(publicKey, pae, signature);
      if (!verified) {
        throw new Error("DSSE signature verification failed");
      }
    } else {
      // The bundle's message digest must be the digest of the artifact being verified.
      const { messageDigest } = bundle.messageSignature;
      const digest = isDigestOnly
        ? data
        : new Uint8Array(await crypto.subtle.digest(HashAlgorithms.SHA256, data as BufferSource));
      if (messageDigest.algorithm !== "SHA2_256" || !uint8ArrayEqual(digest, base64ToUint8Array(messageDigest.digest))) {
        throw new Error("Artifact digest does not match the bundle message digest");
      }
      const publicKey = await signingCert.publicKeyObj;

      if (isDigestOnly) {
        // For hashedrekord bundles, verify signature over the digest directly.
        // Uses the same elliptic.js workaround as sigstore-js conformance CLI.
        const verified = await verifySignatureOverDigest(publicKey, data, signature);
        if (!verified) {
          throw new Error("Error verifying signature over digest");
        }
      } else {
        // For regular bundles, verify the signature over the artifact data
        const verified = await verifySignature(publicKey, data, signature);
        if (!verified) {
          const keyAlg = publicKey.algorithm.name || 'unknown';
          throw new Error(`Error verifying artifact signature. Key algorithm: ${keyAlg}, Data length: ${data.length}, Signature length: ${signature.length}`);
        }
      }
    }

    return true;
  }

public async verifyArtifact(
  identity: string,
  issuer: string,
  bundle: SigstoreBundle,
  data: Uint8Array,
  isDigestOnly: boolean = false,
): Promise<boolean> {

  const policy = new AllOf([
    new Identity({ identity }),
    new AnyOf([
      new OIDCIssuerV2(issuer),
      new OIDCIssuer(issuer),
    ]),
  ]);

  return this.verifyArtifactPolicy(
    policy,
    bundle,
    data,
    isDigestOnly,
  );
}

    

  /**
   * Verify a DSSE bundle using a verification policy.
   * This matches sigstore-python's verify_dsse API.
   *
   * Reference: https://github.com/sigstore/sigstore-python/blob/main/sigstore/verify/verifier.py#L388
   *
   * Unlike verify_artifact which verifies an artifact against a bundle,
   * this method verifies the DSSE envelope itself and returns the payload.
   * The caller is responsible for checking that the payload matches their
   * expected artifact (e.g., by checking subjects in an in-toto statement).
   *
   * @param bundle - The Sigstore bundle containing the DSSE envelope
   * @param policy - A verification policy to apply to the signing certificate
   * @returns The payload type and payload bytes from the verified envelope
   */
  public async verifyDsse(
    bundle: SigstoreBundle,
    policy: VerificationPolicy,
  ): Promise<{ payloadType: string; payload: Uint8Array }> {
    const { signingCert, signature } = await this.verifyBundle(bundle, policy);
    if (!bundle.dsseEnvelope) {
      throw new Error("Bundle does not contain a DSSE envelope");
    }

    // (7) Verify the DSSE envelope signature
    const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
    const pae = preAuthEncoding(bundle.dsseEnvelope.payloadType, payloadBytes);

    const publicKey = await signingCert.publicKeyObj;
    const verified = await verifySignature(publicKey, pae, signature);
    if (!verified) {
      throw new Error("DSSE signature verification failed");
    }

    // (8) Every entry MUST be of type "dsse" for DSSE verification
    for (const entry of bundle.verificationMaterial.tlogEntries) {
      if (entry.kindVersion.kind !== "dsse") {
        throw new Error(`Expected entry type dsse, got ${entry.kindVersion.kind}`);
      }
    }

    // Return the verified payload
    return {
      payloadType: bundle.dsseEnvelope.payloadType,
      payload: payloadBytes,
    };
  }
}
