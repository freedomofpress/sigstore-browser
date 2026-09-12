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
import { assertBundle, type SigstoreBundle, type TLogEntry } from "./bundle.js";
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
import type { VerificationPolicy } from "./policy.js";
import { AnyOf, AllOf, OIDCIssuer, OIDCIssuerV2, Identity } from "./policy.js";

// Upper bound on log entries per bundle, matching sigstore-go's MaxAllowedTlogEntries.
const MAX_TLOG_ENTRIES = 32;

// Returns the bundle version from the media type; unknown media types are rejected like sigstore-go does.
function getBundleVersion(mediaType: string): string {
  const legacy = /^application\/vnd\.dev\.sigstore\.bundle\+json;version=(0\.[123])$/.exec(mediaType);
  const current = /^application\/vnd\.dev\.sigstore\.bundle\.v(\d+\.\d+(?:\.\d+)?)\+json$/.exec(mediaType);
  const version = legacy?.[1] ?? current?.[1];
  if (!version) {
    throw new Error(`Unsupported bundle media type: ${mediaType}`);
  }
  return version;
}

/**
 * Rekor v2 entries omit `integratedTime` and MUST carry a signed RFC3161
 * timestamp instead. Check for actual content, not just presence: an empty
 * `timestampVerificationData: {}` is truthy, so `if (!timestampVerificationData)`
 * is bypassable and leaves the cert validity window unanchored in time.
 */
export function assertRekorV2Timestamp(
  timestampData?: { rfc3161Timestamps?: readonly unknown[] },
): void {
  if (!timestampData?.rfc3161Timestamps?.length) {
    throw new Error("Rekor v2 bundles require a timestamp for verification.");
  }
}

// Returns the bundle's single signature, from either the message signature or the DSSE envelope.
function bundleSignature(bundle: SigstoreBundle): Uint8Array {
  return base64ToUint8Array(
    bundle.messageSignature ? bundle.messageSignature.signature : bundle.dsseEnvelope.signatures[0].sig,
  );
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

  // Loads every Rekor key in the trusted root; entries select their key by log ID.
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
      })),
    );
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
      rekor: await this.loadLog(rawRoot[SigstoreRoots.tlogs]),
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
  // Returns the log IDs of the SCTs that verified; any SCT failing verification is fatal.
  async verifySCT(
    cert: X509Certificate,
    issuer: X509Certificate,
    ctlogs: CTLog[],
  ): Promise<Uint8Array[]> {
    let extSCT: X509SCTExtension | undefined;

    // The SCT signature covers the TBS certificate without the SCT extension, so work on a clone.
    const clone = cert.clone();

    for (let i = 0; i < clone.extensions.length; i++) {
      const ext = clone.extensions[i];

      if (ext.subs[0].toOID() === EXTENSION_OID_SCT) {
        extSCT = new X509SCTExtension(ext);
        clone.extensions.splice(i, 1);
        break;
      }
    }

    if (!extSCT) {
      throw new Error("Certificate is missing required SCT extension");
    }

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

    const issuerId = new Uint8Array(
      await crypto.subtle.digest(HashAlgorithms.SHA256, issuer.publicKey as BufferSource),
    );
    preCert.appendView(issuerId);

    const tbs = clone.tbsCertificate.toDER();
    preCert.appendUint24(tbs.length);
    preCert.appendView(tbs);

    const verifiedSCTs: Uint8Array[] = [];

    for (const sct of extSCT.signedCertificateTimestamps) {
      // Candidate logs share the SCT's log ID and were valid at the SCT time.
      const validCTLogs = ctlogs.filter((log) => {
        if (!uint8ArrayEqual(log.logID, sct.logID)) return false;
        return log.validFor.start <= sct.datetime && sct.datetime <= log.validFor.end;
      });

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

  // Verifies the signed entry timestamp and returns the integrated time it binds.
  private async verifySET(entry: TLogEntry, log: RekorKeyInfo): Promise<Date> {
    const integratedTime = Number(entry.integratedTime);
    const signed = stringToUint8Array(
      canonicalize({
        body: entry.canonicalizedBody,
        integratedTime,
        logIndex: Number(entry.logIndex),
        logID: Uint8ArrayToHex(log.logId),
      }),
    );
    const signature = base64ToUint8Array(entry.inclusionPromise!.signedEntryTimestamp);
    if (!(await verifySignature(log.publicKey, signed, signature, log.hashAlgorithm))) {
      throw new Error("Failed to verify the inclusion promise in the provided bundle.");
    }
    return new Date(integratedTime * 1000);
  }

  // Fully verifies every entry from a known log and returns the SET-bound integrated times.
  // Entries from unknown logs are ignored; the threshold counts distinct logs that verified.
  private async verifyTlogEntries(cert: X509Certificate, bundle: SigstoreBundle): Promise<Date[]> {
    const entries = bundle.verificationMaterial.tlogEntries;
    if (entries.length > MAX_TLOG_ENTRIES) {
      throw new Error(`Too many tlog entries: ${entries.length} > ${MAX_TLOG_ENTRIES}`);
    }
    // Only v0.1 bundles may rely on an inclusion promise alone.
    const requireProof = getBundleVersion(bundle.mediaType) !== "0.1";
    const verifiedLogs = new Set<string>();
    const integratedTimes: Date[] = [];

    for (const entry of entries) {
      const logId = base64ToUint8Array(entry.logId.keyId);
      const log = this.root!.rekor.find((l) => uint8ArrayEqual(l.logId, logId));
      if (!log) continue;

      const hasPromise = entry.inclusionPromise !== undefined;
      if (!entry.inclusionProof && (requireProof || !hasPromise)) {
        throw new Error("Transparency log entry requires an inclusion proof.");
      }
      if (hasPromise) {
        integratedTimes.push(await this.verifySET(entry, log));
      }
      if (entry.inclusionProof) {
        await verifyMerkleInclusion(entry);
        await verifyCheckpoint(entry, log);
      }
      if (entry.integratedTime) {
        if (!cert.validForDate(new Date(Number(entry.integratedTime) * 1000))) {
          throw new Error("Artifact signing was logged outside of the certificate validity.");
        }
      } else {
        assertRekorV2Timestamp(bundle.verificationMaterial.timestampVerificationData);
      }
      await verifyTLogBody(entry, bundle, cert);
      verifiedLogs.add(Uint8ArrayToHex(logId));
    }

    if (verifiedLogs.size < this.options.tlogThreshold) {
      throw new Error(`Not enough verified tlog entries: ${verifiedLogs.size} < ${this.options.tlogThreshold}`);
    }
    return integratedTimes;
  }

  // Shared checks for certificate, policy, transparency log and timestamps; returns the signing certificate.
  private async verifyBundle(
    bundle: SigstoreBundle,
    policy: VerificationPolicy,
    signature: Uint8Array,
  ): Promise<X509Certificate> {
    if (!this.root || !this.rawRoot) {
      throw new Error("Sigstore root is undefined");
    }

    const cert = bundle.verificationMaterial.certificate ||
      bundle.verificationMaterial.x509CertificateChain?.certificates[0];
    if (!cert) {
      throw new Error("No certificate found in bundle");
    }
    const signingCert = X509Certificate.parse(base64ToUint8Array(cert.rawBytes));

    policy.verify(signingCert);

    const certPath = await this.verifyCertificateChain(
      signingCert.notBefore,
      signingCert,
      this.root.certificateAuthorities,
    );
    const issuerCert = certPath.length > 1 ? certPath[1] : certPath[0];
    const verifiedSCTs = await this.verifySCT(signingCert, issuerCert, this.root.ctlogs);
    if (verifiedSCTs.length < this.options.ctlogThreshold) {
      throw new Error(
        `Not enough valid SCTs: found ${verifiedSCTs.length}, required ${this.options.ctlogThreshold}`,
      );
    }

    await this.verifyTlogEntries(signingCert, bundle);

    const verifiedTimestamps = await verifyBundleTimestamp(
      bundle.verificationMaterial.timestampVerificationData,
      signature,
      this.rawRoot.timestampAuthorities || [],
    );
    if (verifiedTimestamps.length < this.options.tsaThreshold) {
      throw new Error(
        `Not enough verified TSA timestamps: ${verifiedTimestamps.length} < ${this.options.tsaThreshold}`,
      );
    }
    for (const ts of verifiedTimestamps) {
      if (!signingCert.validForDate(ts)) {
        throw new Error("Certificate was not valid at the time of timestamping");
      }
    }

    return signingCert;
  }

  public async verifyArtifactPolicy(
    policy: VerificationPolicy,
    bundle: SigstoreBundle,
    data: Uint8Array,
    isDigestOnly: boolean = false,
  ): Promise<boolean> {
    assertBundle(bundle);
    const signature = bundleSignature(bundle);
    const signingCert = await this.verifyBundle(bundle, policy, signature);
    const publicKey = await signingCert.publicKeyObj;

    if (bundle.dsseEnvelope) {
      const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
      const artifactDigest = Uint8ArrayToHex(
        isDigestOnly ? data : new Uint8Array(await crypto.subtle.digest(HashAlgorithms.SHA256, data as BufferSource)),
      );
      const subjects = JSON.parse(Uint8ArrayToString(payloadBytes)).subject;
      const matched = Array.isArray(subjects) && subjects.some(
        (s) => typeof s?.digest?.sha256 === "string" && s.digest.sha256.toLowerCase() === artifactDigest,
      );
      if (!matched) {
        throw new Error(`Artifact digest ${artifactDigest} does not match any subject in DSSE payload`);
      }
      const pae = preAuthEncoding(bundle.dsseEnvelope.payloadType, payloadBytes);
      if (!(await verifySignature(publicKey, pae, signature))) {
        throw new Error("DSSE signature verification failed");
      }
    } else {
      const { messageDigest } = bundle.messageSignature;
      if (messageDigest.algorithm !== "SHA2_256") {
        throw new Error(`Unsupported message digest algorithm: ${messageDigest.algorithm}`);
      }
      const digest = isDigestOnly
        ? data
        : new Uint8Array(await crypto.subtle.digest(HashAlgorithms.SHA256, data as BufferSource));
      if (!uint8ArrayEqual(digest, base64ToUint8Array(messageDigest.digest))) {
        throw new Error("Artifact digest does not match the bundle message digest");
      }
      // WebCrypto always hashes its input, so a bare digest is verified with the low-level ECDSA path.
      const verified = isDigestOnly
        ? await verifySignatureOverDigest(publicKey, data, signature)
        : await verifySignature(publicKey, data, signature);
      if (!verified) {
        throw new Error("Error verifying artifact signature");
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

    return this.verifyArtifactPolicy(policy, bundle, data, isDigestOnly);
  }

  /**
   * Verify a DSSE bundle using a verification policy and return its payload.
   * This matches sigstore-python's verify_dsse API; the caller must check that the payload
   * describes the expected artifact.
   *
   * Reference: https://github.com/sigstore/sigstore-python/blob/main/sigstore/verify/verifier.py#L388
   */
  public async verifyDsse(
    bundle: SigstoreBundle,
    policy: VerificationPolicy,
  ): Promise<{ payloadType: string; payload: Uint8Array }> {
    assertBundle(bundle);
    if (!bundle.dsseEnvelope) {
      throw new Error("Bundle does not contain a DSSE envelope");
    }
    for (const entry of bundle.verificationMaterial.tlogEntries) {
      if (entry.kindVersion.kind !== "dsse") {
        throw new Error(`Expected entry type dsse, got ${entry.kindVersion.kind}`);
      }
    }

    const signature = bundleSignature(bundle);
    const signingCert = await this.verifyBundle(bundle, policy, signature);

    const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
    const pae = preAuthEncoding(bundle.dsseEnvelope.payloadType, payloadBytes);
    if (!(await verifySignature(await signingCert.publicKeyObj, pae, signature))) {
      throw new Error("DSSE signature verification failed");
    }

    return { payloadType: bundle.dsseEnvelope.payloadType, payload: payloadBytes };
  }
}
