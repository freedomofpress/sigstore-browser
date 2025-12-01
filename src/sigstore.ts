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
import { SigstoreBundle } from "./bundle.js";
import { preAuthEncoding } from "./dsse.js";
import {
  CertAuthority,
  CTLog,
  RawCAs,
  RawLogs,
  RawTimestampAuthorities,
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

const MEDIA_TYPE_BASE = "application/vnd.dev.sigstore.bundle";

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
    // Basic semver validation (major.minor or major.minor.patch)
    if (/^\d+\.\d+(\.\d+)?$/.test(version)) {
      return version;
    }
  }

  // Default to 0.1 for unknown formats
  return "0.1";
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
  }

  async loadLog(frozenTimestamp: Date, logs: RawLogs): Promise<RekorKeyInfo | undefined> {
    // Load the first Rekor transparency log key that's valid at the frozen timestamp
    // and store its log ID for verification. This matches sigstore-go's approach of
    // looking up the verifier by log ID (verify/tlog.go:80-83).

    for (const log of logs) {
      // if start date is not in the future, and if an end doesn't exist or is in the future
      if (
        frozenTimestamp > new Date(log.publicKey.validFor.start) &&
        (!log.publicKey.validFor.end ||
          new Date(log.publicKey.validFor.end) > frozenTimestamp)
      ) {
        return {
          publicKey: await importKey(
            log.publicKey.keyDetails,
            log.publicKey.keyDetails,
            log.publicKey.rawBytes,
          ),
          logId: base64ToUint8Array(log.logId.keyId),
        };
      }
    }

    // Return undefined instead of throwing - some bundles don't need Rekor keys
    // (e.g., v0.3 bundles with inclusion proofs)
    return undefined;
  }

  async loadCTLogs(frozenTimestamp: Date, ctlogs: RawLogs): Promise<CTLog[]> {
    const result: CTLog[] = [];

    for (const log of ctlogs) {
      const start = new Date(log.publicKey.validFor.start);
      const end = log.publicKey.validFor.end
        ? new Date(log.publicKey.validFor.end)
        : new Date('9999-12-31'); // No expiry means valid forever

      // Include logs that are valid (started before frozen timestamp)
      // We keep all logs, even expired ones, for historical verification
      if (start <= frozenTimestamp) {
        const publicKey = await importKey(
          log.publicKey.keyDetails,
          log.publicKey.keyDetails,
          log.publicKey.rawBytes,
        );

        result.push({
          logID: base64ToUint8Array(log.logId.keyId),
          publicKey,
          validFor: { start, end },
        });
      }
    }

    if (result.length === 0) {
      throw new Error("Could not find any valid CT logs in sigstore root.");
    }

    return result;
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

  // Load timestamp authorities that are valid at the frozen timestamp.
  // Unlike sigstore-js which doesn't pre-load TSAs (it passes raw TSA data to timestamp verification),
  // we parse and filter them at initialization time for consistency with how we handle CAs and other roots.
  loadTSA(
    frozenTimestamp: Date,
    tsas?: RawTimestampAuthorities,
  ): CertAuthority[] {
    if (!tsas || tsas.length === 0) {
      return [];
    }

    const result: CertAuthority[] = [];

    for (const tsa of tsas) {
      const start = new Date(tsa.validFor.start);
      const end = tsa.validFor.end ? new Date(tsa.validFor.end) : new Date(8640000000000000);

      if (frozenTimestamp > start && frozenTimestamp < end) {
        const certChain = tsa.certChain.certificates.map(cert =>
          X509Certificate.parse(base64ToUint8Array(cert.rawBytes))
        );

        if (certChain.length > 0) {
          result.push({
            certChain,
            validFor: { start, end },
          });
        }
      }
    }

    return result;
  }

  // Load certificate authorities (Fulcio CAs) that are valid at the frozen timestamp.
  // Similar to sigstore-js's filterCertAuthorities() in trust/filter.ts, but we also
  // parse the certificates at load time whereas sigstore-js keeps them in the trust material
  // and parses them during verification. This pre-loading approach is consistent with our
  // architecture of loading all trusted roots at initialization.
  loadCA(frozenTimestamp: Date, cas: RawCAs): CertAuthority[] {
    const result: CertAuthority[] = [];

    for (const ca of cas) {
      const start = new Date(ca.validFor.start);
      const end = ca.validFor.end ? new Date(ca.validFor.end) : new Date(8640000000000000);

      if (frozenTimestamp > start && frozenTimestamp < end) {
        const certChain = ca.certChain.certificates.map(cert =>
          X509Certificate.parse(base64ToUint8Array(cert.rawBytes))
        );

        if (certChain.length > 0) {
          result.push({
            certChain,
            validFor: { start, end },
          });
        }
      }
    }

    return result;
  }

  async loadSigstoreRoot(rawRoot: TrustedRoot) {
    const frozenTimestamp = new Date();

    this.rawRoot = rawRoot;
    this.root = {
      rekor: await this.loadLog(frozenTimestamp, rawRoot[SigstoreRoots.tlogs]),
      ctlogs: await this.loadCTLogs(frozenTimestamp, rawRoot[SigstoreRoots.ctlogs]),
      certificateAuthorities: this.loadCA(
        frozenTimestamp,
        rawRoot[SigstoreRoots.certificateAuthorities],
      ),
      timestampAuthorities: this.loadTSA(frozenTimestamp, rawRoot.timestampAuthorities),
    };
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
  // - Returns array of verified SCT logIDs for threshold checking (matches reference behavior)
  async verifySCT(
    cert: X509Certificate,
    issuer: X509Certificate,
    ctlogs: CTLog[],
  ): Promise<Uint8Array[]> {
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
      await crypto.subtle.digest(HashAlgorithms.SHA256, issuer.publicKey as Uint8Array<ArrayBuffer>),
    );
    preCert.appendView(issuerId);

    // Re-encodes the certificate to DER after removing the SCT extension
    const tbs = clone.tbsCertificate.toDER();
    preCert.appendUint24(tbs.length);
    preCert.appendView(tbs);

    // Calculate and return the verification results for each SCT
    // Unlike sigstore-go which counts verified SCTs and checks threshold at the end,
    // sigstore-js throws immediately if any SCT fails verification
    const verifiedSCTs: Uint8Array[] = [];

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
              return true;
            }
          } catch {
            // Continue trying other logs
          }
        }
        return false;
      })();

      if (!verified) {
        throw new Error("SCT verification failed");
      }

      verifiedSCTs.push(sct.logID);
    }

    return verifiedSCTs;
  }

  async verifyInclusionPromise(
    cert: X509Certificate,
    bundle: SigstoreBundle,
    rekor: RekorKeyInfo | undefined,
  ): Promise<boolean> {
    const entries = bundle.verificationMaterial.tlogEntries;

    // Check that bundle has enough tlog entries to meet threshold
    if (entries.length < this.options.tlogThreshold) {
      throw new Error(
        `Not enough tlog entries: ${entries.length} < ${this.options.tlogThreshold}`,
      );
    }

    // Prevent DoS via excessive entries and threshold bypass via duplicates
    // Matches sigstore-go limits (verify/tlog.go:46-57)
    const MAX_TLOG_ENTRIES = 32;
    if (entries.length > MAX_TLOG_ENTRIES) {
      throw new Error(
        `Too many tlog entries: ${entries.length} > ${MAX_TLOG_ENTRIES}`,
      );
    }

    for (let i = 0; i < entries.length; i++) {
      for (let j = i + 1; j < entries.length; j++) {
        const iLogId = Uint8ArrayToHex(base64ToUint8Array(entries[i].logId.keyId));
        const jLogId = Uint8ArrayToHex(base64ToUint8Array(entries[j].logId.keyId));
        if (iLogId === jLogId && entries[i].logIndex === entries[j].logIndex) {
          throw new Error(
            `Duplicate tlog entry found: logID=${iLogId}, logIndex=${entries[i].logIndex}`,
          );
        }
      }
    }

    const entry = entries[0];

    // Extract bundle version from mediaType
    // Reference: https://github.com/sigstore/sigstore-go/blob/main/pkg/bundle/bundle.go#L159-L177
    const bundleVersion = getBundleVersion(bundle.mediaType);
    const isV02OrLater = parseFloat(bundleVersion) >= 0.2;

    // Bundle v0.2+ requires an inclusion proof
    if (isV02OrLater && !entry.inclusionProof) {
      throw new Error(
        "Bundle v0.2+ requires an inclusion proof.",
      );
    }

    // For rekor2/v0.3 bundles with inclusion proofs, the inclusion promise is optional
    if (!entry.inclusionPromise?.signedEntryTimestamp) {
      // If there's no inclusion promise, there must be an inclusion proof
      if (!entry.inclusionProof) {
        throw new Error(
          "Bundle must have either an inclusion promise or an inclusion proof.",
        );
      }
    } else {
      // Verify the inclusion promise signature if present
      // For v0.3 bundles that have both inclusion promise and proof,
      // we can skip the promise verification if we don't have a Rekor key
      // and there's a valid inclusion proof
      if (!rekor && entry.inclusionProof) {
        // Skip promise verification if we have an inclusion proof
        // The inclusion proof will be verified later
      } else {
        if (!rekor) {
          throw new Error("Rekor public key not found in trusted root");
        }

        // Verify the log ID matches (matches sigstore-go verify/tlog.go:80-83)
        const entryLogId = base64ToUint8Array(entry.logId.keyId);
        if (!uint8ArrayEqual(rekor.logId, entryLogId)) {
          throw new Error(
            `Rekor log ID mismatch: bundle uses ${Uint8ArrayToHex(entryLogId)} but loaded key is for ${Uint8ArrayToHex(rekor.logId)}`
          );
        }

        const signature = base64ToUint8Array(
          entry.inclusionPromise.signedEntryTimestamp,
        );

        const keyId = Uint8ArrayToHex(entryLogId);
        const integratedTime = Number(entry.integratedTime);

        const signed = stringToUint8Array(
          canonicalize({
            body: entry.canonicalizedBody,
            integratedTime: integratedTime,
            logIndex: Number(entry.logIndex),
            logID: keyId,
          }),
        );

        if (!(await verifySignature(rekor.publicKey, signed, signature))) {
          throw new Error(
            "Failed to verify the inclusion promise in the provided bundle.",
          );
        }
      }
    }

    // Validate integrated time and logged certificate
    // Note: Rekor v2 bundles don't have integrated time in the tlog entry
    if (entry.integratedTime) {
      const integratedTime = Number(entry.integratedTime);
      const integratedDate = new Date(integratedTime * 1000);

      if (!cert.validForDate(integratedDate)) {
        throw new Error(
          "Artifact signing was logged outside of the certificate validity.",
        );
      }
    } else {
      // Rekor v2 bundles (no integratedTime) require a timestamp for verification
      if (!bundle.verificationMaterial.timestampVerificationData) {
        throw new Error(
          "Rekor v2 bundles require a timestamp for verification.",
        );
      }
    }

    // Verify that the certificate in the log matches the signing certificate
    // The format depends on the entry type (hashedrekord vs dsse) and version
    const bodyJson = JSON.parse(Uint8ArrayToString(base64ToUint8Array(entry.canonicalizedBody)));

    if (bodyJson.kind === "hashedrekord") {
      let loggedCertContent: string | undefined;

      // Check for hashedRekordV002 structure (Rekor v2)
      if (bodyJson.spec.hashedRekordV002) {
        const verifier = bodyJson.spec.hashedRekordV002.signature.verifier;
        if (verifier?.x509Certificate) {
          loggedCertContent = verifier.x509Certificate.rawBytes;
        }
      }
      // Check for older hashedrekord structure
      else if (bodyJson.spec.signature?.publicKey) {
        loggedCertContent = bodyJson.spec.signature.publicKey.content;
      }

      if (loggedCertContent) {
        // For hashedrekord v0.0.1, publicKey.content is base64-encoded PEM
        // For hashedRekordV002, x509Certificate.rawBytes is base64-encoded DER
        let loggedCert: X509Certificate;
        if (bodyJson.spec.hashedRekordV002) {
          loggedCert = X509Certificate.parse(base64ToUint8Array(loggedCertContent));
        } else {
          const pemString = Uint8ArrayToString(base64ToUint8Array(loggedCertContent));
          loggedCert = X509Certificate.parse(pemString);
        }

        if (!cert.equals(loggedCert)) {
          throw new Error(
            "Certificate in Rekor log does not match the signing certificate.",
          );
        }
      }
    } else if (bodyJson.kind === "dsse") {
      // DSSE entries store signatures differently
      // The certificate is verified through the bundle's verification material
      // No additional check needed here
    } else if (bodyJson.kind === "intoto") {
      // Intoto entries are DSSE-based and don't store certificates in the tlog entry
      // The certificate is part of the bundle's verification material which has already
      // been verified against the CA root. The intoto verification in tlog/intoto.ts
      // verifies the signature and payload hash match between the tlog and bundle.
    } else {
      // Unknown entry type - this should not happen with standard Sigstore bundles
      throw new Error(`Unsupported tlog entry kind: ${bodyJson.kind}`);
    }

    return true;
  }

  async verifyInclusionProof(bundle: SigstoreBundle): Promise<void> {
    if (!this.rawRoot) {
      throw new Error("Sigstore root is undefined");
    }

    if (bundle.verificationMaterial.tlogEntries.length < 1) {
      throw new Error("No transparency log entries found in bundle");
    }

    // Verify inclusion proof for ALL entries, not just the first one
    // Reference: https://github.com/sigstore/sigstore-go/blob/main/pkg/verify/tlog.go#L74-L127
    for (const entry of bundle.verificationMaterial.tlogEntries) {
      // Only verify if there's an inclusion proof (v0.3/rekor2 bundles)
      // v0.1 bundles use inclusion promises instead, verified in verifyInclusionPromise
      if (entry.inclusionProof) {
        await verifyMerkleInclusion(entry);

        if (entry.inclusionProof.checkpoint) {
          await verifyCheckpoint(entry, this.rawRoot.tlogs);
        }
      }
    }
  }

  public async verifyArtifact(
    identity: string,
    issuer: string,
    bundle: SigstoreBundle,
    data: Uint8Array,
    isDigestOnly: boolean = false,
  ): Promise<boolean> {
    // Quick checks first: does the signing certificate have the correct identity?

    if (!this.root) {
      throw new Error("Sigstore root is undefined");
    }

    const cert = bundle.verificationMaterial.certificate ||
      bundle.verificationMaterial.x509CertificateChain?.certificates[0];

    if (!cert) {
      throw new Error("No certificate found in bundle");
    }

    const signingCert = X509Certificate.parse(base64ToUint8Array(cert.rawBytes));

    // Handle both regular bundles (messageSignature) and DSSE bundles (dsseEnvelope)
    let signature: Uint8Array;
    if (bundle.messageSignature) {
      signature = base64ToUint8Array(bundle.messageSignature.signature);
    } else if (bundle.dsseEnvelope) {
      if (!bundle.dsseEnvelope.signatures || bundle.dsseEnvelope.signatures.length === 0) {
        throw new Error("DSSE envelope has no signatures");
      }
      signature = base64ToUint8Array(bundle.dsseEnvelope.signatures[0].sig);
    } else {
      throw new Error("Bundle does not contain a message signature or DSSE envelope");
    }

    // # 1 Basic stuff
    if (signingCert.subjectAltName !== identity) {
      throw new Error(
        "Certificate identity (subjectAltName) do not match the verifying one.",
      );
    }

    // Check for issuer - try V2 first, fall back to V1 (like sigstore-js does)
    const certIssuer = signingCert.extFulcioIssuerV2?.issuer || signingCert.extFulcioIssuerV1?.issuer;
    if (certIssuer !== issuer) {
      throw new Error("Identity issuer is not the verifying one.");
    }

    // # 2 Certificate validity - verify chain to trusted CA
    // Similar to sigstore-js key/index.ts:59-64 which calls verifyCertificateChain()
    // Returns the verified certificate path [leaf, intermediate(s), root]
    const certPath = await this.verifyCertificateChain(
      signingCert.notBefore,
      signingCert,
      this.root.certificateAuthorities
    );

    // # 3 To verify the SCT we need to build a preCert (because the cert was logged without the SCT)
    // https://github.com/sigstore/sigstore-js/packages/verify/src/key/sct.ts#L45
    // Similar to sigstore-js key/index.ts:67 which uses path[0] (leaf) and path[1] (issuer)
    // for SCT verification. Handle edge case where path has only one cert (self-signed root).
    const issuerCert = certPath.length > 1 ? certPath[1] : certPath[0];
    const verifiedSCTs = await this.verifySCT(signingCert, issuerCert, this.root.ctlogs);
    if (verifiedSCTs.length < this.options.ctlogThreshold) {
      throw new Error(
        `Not enough valid SCTs: found ${verifiedSCTs.length}, required ${this.options.ctlogThreshold}`
      );
    }

    // # 4 Rekor inclusion promise
    if (
      !(await this.verifyInclusionPromise(signingCert, bundle, this.root.rekor))
    ) {
      throw new Error("Inclusion promise validation failed.");
    }

    // # 5 Rekor inclusion proof (Merkle tree verification)
    await this.verifyInclusionProof(bundle);

    // # 5.1 Rekor body verification - verify ALL entries (matches sigstore-js verifier.ts:147)
    for (const entry of bundle.verificationMaterial.tlogEntries) {
      await verifyTLogBody(entry, bundle);
    }

    // # 6 TSA Timestamp Verification
    // Verify all timestamps and enforce threshold
    // Reference: https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/verifier.ts#L101-L106
    const verifiedTimestamps = await verifyBundleTimestamp(
      bundle.verificationMaterial.timestampVerificationData,
      signature,
      this.rawRoot?.timestampAuthorities || []
    );

    if (verifiedTimestamps.length < this.options.tsaThreshold) {
      throw new Error(
        `Not enough verified TSA timestamps: ${verifiedTimestamps.length} < ${this.options.tsaThreshold}`
      );
    }

    // If we have verified timestamps, check certificate validity at each timestamp time
    for (const verifiedTimestamp of verifiedTimestamps) {
      if (!signingCert.validForDate(verifiedTimestamp)) {
        throw new Error(
          "Certificate was not valid at the time of timestamping"
        );
      }
    }

    // # 7 Revocation *skipping* not really a thing (unsurprisingly)

    // # 8 verify the signed data
    if (bundle.dsseEnvelope) {
      // For DSSE bundles, verify the signature over the PAE
      const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
      const payload = JSON.parse(Uint8ArrayToString(payloadBytes));

      // Verify the artifact digest matches a subject in the in-toto statement
      if (!payload.subject || payload.subject.length === 0) {
        throw new Error("DSSE payload has no subject");
      }

      // Compute or extract the artifact digest
      let artifactDigest: string;
      if (isDigestOnly) {
        // data is already the digest bytes
        artifactDigest = Uint8ArrayToHex(data);
      } else {
        // data is the file content, compute the digest
        artifactDigest = Uint8ArrayToHex(
          new Uint8Array(await crypto.subtle.digest(HashAlgorithms.SHA256, data as Uint8Array<ArrayBuffer>))
        );
      }

      // Find matching subject by scanning all subjects (not just [0])
      let matchedSubject = null;
      for (const subject of payload.subject) {
        const subjectDigest = subject.digest?.["sha256"];
        if (subjectDigest && artifactDigest === subjectDigest.toLowerCase()) {
          matchedSubject = subject;
          break;
        }
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
}
