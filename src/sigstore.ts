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

// Returns the bundle's single signature, from either the message signature or the DSSE envelope.
function bundleSignature(bundle: SigstoreBundle): Uint8Array {
  return base64ToUint8Array(
    bundle.messageSignature ? bundle.messageSignature.signature : bundle.dsseEnvelope.signatures[0].sig,
  );
}

// Converts a trusted root validity window to dates; a missing end means no expiry.
function validity(v: { start: string; end?: string }): { start: Date; end: Date } {
  return { start: new Date(v.start), end: v.end ? new Date(v.end) : new Date(8640000000000000) };
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
        validFor: validity(log.publicKey.validFor),
      })),
    );
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

  // Loads every Fulcio CA; verifyCertificateChain() selects CAs by the observer timestamp.
  loadCA(cas: RawCAs): CertAuthority[] {
    return cas
      .filter((ca) => ca.certChain.certificates.length > 0)
      .map((ca) => ({
        certChain: ca.certChain.certificates.map((cert) =>
          X509Certificate.parse(base64ToUint8Array(cert.rawBytes)),
        ),
        validFor: validity(ca.validFor),
      }));
  }

  async loadSigstoreRoot(rawRoot: TrustedRoot) {
    this.rawRoot = rawRoot;
    this.root = {
      rekor: await this.loadLog(rawRoot[SigstoreRoots.tlogs]),
      ctlogs: await this.loadCTLogs(rawRoot[SigstoreRoots.ctlogs]),
      certificateAuthorities: this.loadCA(rawRoot[SigstoreRoots.certificateAuthorities]),
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
      if (entry.integratedTime && !cert.validForDate(new Date(Number(entry.integratedTime) * 1000))) {
        throw new Error("Artifact signing was logged outside of the certificate validity.");
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

    // Observer timestamps come from SET-bound integrated times and verified RFC 3161 timestamps.
    // Rekor v2 entries carry no integrated time, so they need a TSA timestamp to be anchored at all.
    const integratedTimes = await this.verifyTlogEntries(signingCert, bundle);
    const tsaTimes = await verifyBundleTimestamp(
      bundle.verificationMaterial.timestampVerificationData,
      signature,
      this.rawRoot.timestampAuthorities || [],
    );
    if (tsaTimes.length < this.options.tsaThreshold) {
      throw new Error(`Not enough verified TSA timestamps: ${tsaTimes.length} < ${this.options.tsaThreshold}`);
    }
    const observerTimes = [...integratedTimes, ...tsaTimes];
    if (observerTimes.length === 0) {
      throw new Error("No verified observer timestamp anchors the signature in time.");
    }

    // The CA window and the whole chain are checked at every observer time, never at the leaf's own notBefore.
    let certPath: X509Certificate[] = [];
    for (const ts of observerTimes) {
      certPath = await this.verifyCertificateChain(ts, signingCert, this.root.certificateAuthorities);
    }
    const issuerCert = certPath.length > 1 ? certPath[1] : certPath[0];
    const verifiedSCTs = await this.verifySCT(signingCert, issuerCert, this.root.ctlogs);
    if (verifiedSCTs.length < this.options.ctlogThreshold) {
      throw new Error(
        `Not enough valid SCTs: found ${verifiedSCTs.length}, required ${this.options.ctlogThreshold}`,
      );
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
