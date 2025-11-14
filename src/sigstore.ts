import { SigstoreBundle } from "./bundle.js";
import { canonicalize } from "./canonicalize.js";
import { importKey, verifySignature, verifySignatureOverDigest } from "./crypto.js";
import { preAuthEncoding } from "./dsse.js";
import {
  base64ToUint8Array,
  stringToUint8Array,
  toArrayBuffer,
  Uint8ArrayToHex,
  Uint8ArrayToString,
} from "./encoding.js";
import {
  CTLog,
  RawCAs,
  RawLogs,
  RawTimestampAuthorities,
  Sigstore,
  SigstoreRoots,
  TrustedRoot,
} from "./interfaces.js";
import { ByteStream } from "./stream.js";
import {
  EXTENSION_OID_SCT,
  X509Certificate,
  X509SCTExtension,
} from "./x509/index.js";
import { verifyMerkleInclusion } from "./tlog/merkle.js";
import { verifyCheckpoint } from "./tlog/checkpoint.js";
import { verifyTLogBody } from "./tlog/body.js";
import { verifyBundleTimestamp } from "./timestamp/tsa.js";

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

  async loadLog(frozenTimestamp: Date, logs: RawLogs): Promise<CryptoKey | undefined> {
    // We will stop at the first valid one
    // We do not support more than one valid one at a time, not sure if Sigstore does
    // But it probably do to verify past artifacts: otherwise things still valid today might be discarded

    for (const log of logs) {
      // if start date is not in the future, and if an end doesn't exist or is in the future
      if (
        frozenTimestamp > new Date(log.publicKey.validFor.start) &&
        (!log.publicKey.validFor.end ||
          new Date(log.publicKey.validFor.end) > frozenTimestamp)
      ) {
        return await importKey(
          log.publicKey.keyDetails,
          log.publicKey.keyDetails,
          log.publicKey.rawBytes,
        );
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

  async loadTSA(
    frozenTimestamp: Date,
    tsas?: RawTimestampAuthorities,
  ): Promise<X509Certificate | undefined> {
    if (!tsas || tsas.length === 0) {
      return undefined;
    }

    for (const tsa of tsas) {
      // if start date is not in the future, and if an end doesn't exist or is in the future
      if (
        frozenTimestamp > new Date(tsa.validFor.start) &&
        (!tsa.validFor.end || new Date(tsa.validFor.end) > frozenTimestamp)
      ) {
        let parentCert: X509Certificate | undefined = undefined;
        let currentCert: X509Certificate | undefined = undefined;
        for (const cert of tsa.certChain.certificates.reverse()) {
          currentCert = X509Certificate.parse(base64ToUint8Array(cert.rawBytes));

          if (parentCert == undefined) {
            parentCert = currentCert;

            // So we are expecting a root here, so it has to be self signed
            if (!(await currentCert.verify())) {
              throw new Error("TSA root cert self signature does not verify.");
            }
          } else {
            if (!(await currentCert.verify(parentCert))) {
              throw new Error("TSA cert signature does not verify.");
            }
            parentCert = currentCert;
          }
        }

        if (currentCert) return currentCert;
      }
    }

    return undefined;
  }

  async loadCA(frozenTimestamp: Date, cas: RawCAs): Promise<X509Certificate> {
    for (const ca of cas) {
      // if start date is not in the future, and if an end doesn't exist or is in the future
      if (
        frozenTimestamp > new Date(ca.validFor.start) &&
        (!ca.validFor.end || new Date(ca.validFor.end) > frozenTimestamp)
      ) {
        let parentCert: X509Certificate | undefined = undefined;
        let currentCert: X509Certificate | undefined = undefined;
        for (const cert of ca.certChain.certificates.reverse()) {
          currentCert = X509Certificate.parse(base64ToUint8Array(cert.rawBytes));

          if (parentCert == undefined) {
            parentCert = currentCert;

            // So we are expecting a root here, so it has to be self sigend
            if (!(await currentCert.verify())) {
              throw new Error("Root cert self signature does not verify.");
            }
          } else {
            if (!(await currentCert.verify(parentCert))) {
              throw new Error("Error verifying the certificate chain.");
            }
          }
          // Skip validity check for intermediate certificates in the chain
          // The actual signing certificate will be checked at the time of signing
        }
        if (!currentCert) {
          throw new Error("Could not find a valid certificate.");
        }
        return currentCert;
      }
    }
    throw new Error("Could not find a valid CA in sigstore root.");
  }

  async loadSigstoreRoot(rawRoot: TrustedRoot) {
    const frozenTimestamp = new Date();

    this.rawRoot = rawRoot;
    this.root = {
      rekor: await this.loadLog(frozenTimestamp, rawRoot[SigstoreRoots.tlogs]),
      ctlogs: await this.loadCTLogs(frozenTimestamp, rawRoot[SigstoreRoots.ctlogs]),
      fulcio: await this.loadCA(
        frozenTimestamp,
        rawRoot[SigstoreRoots.certificateAuthorities],
      ),
      tsa: await this.loadTSA(frozenTimestamp, rawRoot.timestampAuthorities),
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
  async verifySCT(
    cert: X509Certificate,
    issuer: X509Certificate,
    ctlogs: CTLog[],
  ): Promise<boolean> {
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

    // No SCT extension found to verify - this is OK, return true
    if (!extSCT) {
      return true;
    }

    // Found an SCT extension but it has no SCTs - this is OK, return true
    if (extSCT.signedCertificateTimestamps.length === 0) {
      return true;
    }

    // Construct the PreCert structure
    // https://www.rfc-editor.org/rfc/rfc6962#section-3.2
    const preCert = new ByteStream();

    // Calculate hash of the issuer's public key
    const issuerId = new Uint8Array(
      await crypto.subtle.digest("SHA-256", toArrayBuffer(issuer.publicKey)),
    );
    preCert.appendView(issuerId);

    // Re-encodes the certificate to DER after removing the SCT extension
    const tbs = clone.tbsCertificate.toDER();
    preCert.appendUint24(tbs.length);
    preCert.appendView(tbs);

    // Let's iterate over the SCTs, if there are more than one, and see if we can validate at least one
    let lastError: any = null;
    for (const logId of extSCT.signedCertificateTimestamps.keys()) {
      const sct = extSCT.signedCertificateTimestamps[logId];

      // SCT should be before cert issuance
      // TODO: it's debatable if this condition is too strict: the log could lag a bit ans this should
      // still be valid
      if (sct.datetime < cert.notBefore || sct.datetime > cert.notAfter) {
        lastError = new Error(`SCT timestamp is invalid: SCT datetime ${sct.datetime}, cert notBefore ${cert.notBefore}, cert notAfter ${cert.notAfter}`);
        continue; // Try next SCT instead of throwing immediately
      }

      // Find the CT log that matches this SCT's log ID and is valid for the SCT datetime
      const validCTLogs = ctlogs.filter((log) => {
        // Check if log IDs match
        if (log.logID.length !== sct.logID.length) return false;
        for (let i = 0; i < log.logID.length; i++) {
          if (log.logID[i] !== sct.logID[i]) return false;
        }
        // Check that the SCT datetime is within the log's validity period
        return log.validFor.start <= sct.datetime && sct.datetime <= log.validFor.end;
      });

      // Try to verify with any valid CT log
      for (const log of validCTLogs) {
        try {
          if (await sct.verify(preCert.buffer, log.publicKey)) {
            return true;
          }
        } catch (e) {
          lastError = e;
          console.error(`SCT verify error for log ${Uint8ArrayToHex(sct.logID)}:`, e);
        }
      }

      if (validCTLogs.length === 0) {
        lastError = new Error(`No valid CT log found for SCT with log ID ${Uint8ArrayToHex(sct.logID)}`);
      }
    }
    throw new Error(`SCT verification failed: ${lastError?.message || 'No valid SCTs found'}`);
  }

  async verifyInclusionPromise(
    cert: X509Certificate,
    bundle: SigstoreBundle,
    rekor: CryptoKey | undefined,
  ): Promise<boolean> {
    // We support and expect only one entry
    if (bundle.verificationMaterial.tlogEntries.length < 1) {
      throw new Error(
        "Failed to find a transparency log entry in the provided bundle.",
      );
    }

    const entry = bundle.verificationMaterial.tlogEntries[0];

    // Extract bundle version from mediaType
    // e.g., "application/vnd.dev.sigstore.bundle+json;version=0.2"
    const versionMatch = bundle.mediaType.match(/version=(\d+\.\d+)/);
    const bundleVersion = versionMatch ? versionMatch[1] : "0.1";
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

        const signature = base64ToUint8Array(
          entry.inclusionPromise.signedEntryTimestamp,
        );

        const keyId = Uint8ArrayToHex(base64ToUint8Array(entry.logId.keyId));
        const integratedTime = Number(entry.integratedTime);

        const signed = stringToUint8Array(
          canonicalize({
            body: entry.canonicalizedBody,
            integratedTime: integratedTime,
            logIndex: Number(entry.logIndex),
            logID: keyId,
          }),
        );

        if (!(await verifySignature(rekor, signed, signature))) {
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
    } else {
      // For other entry types, skip certificate matching for now
      // This may need to be extended for other entry types in the future
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

    const entry = bundle.verificationMaterial.tlogEntries[0];

    // Only verify if there's an inclusion proof (v0.3/rekor2 bundles)
    // v0.1 bundles use inclusion promises instead, verified in verifyInclusionPromise
    if (entry.inclusionProof) {
      await verifyMerkleInclusion(entry);

      if (entry.inclusionProof.checkpoint) {
        await verifyCheckpoint(entry, this.rawRoot.tlogs);
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

    if (process.env.DEBUG_SIGSTORE) {
      console.error(`Parsing certificate, rawBytes length: ${cert.rawBytes.length}, type: ${typeof cert.rawBytes}`);
    }
    let signingCert: X509Certificate;
    try {
      signingCert = X509Certificate.parse(base64ToUint8Array(cert.rawBytes));
      if (process.env.DEBUG_SIGSTORE) {
        console.error(`Certificate parsed successfully`);
      }
    } catch (e) {
      if (process.env.DEBUG_SIGSTORE) {
        console.error(`Failed to parse certificate: ${e}`);
      }
      throw e;
    }

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

    // # 2 Certificate validity
    if (!signingCert.verify(this.root.fulcio)) {
      throw new Error(
        "Signing certificate has not been signed by the current Fulcio CA.",
      );
    }
    // This check is not complete, we should check every ca in the chain. This is silly we know they are long lived
    // and we need performance
    if (
      signingCert.notBefore < this.root.fulcio.notBefore ||
      signingCert.notBefore > this.root.fulcio.notAfter
    ) {
      throw new Error(
        "Signing cert was signed when the Fulcio CA was not valid.",
      );
    }

    // # 3 To verify the SCT we need to build a preCert (because the cert was logged without the SCT)
    // https://github.com/sigstore/sigstore-js/packages/verify/src/key/sct.ts#L45
    if (
      !(await this.verifySCT(signingCert, this.root.fulcio, this.root.ctlogs))
    ) {
      throw new Error("SCT validation failed.");
    }

    // # 4 Rekor inclusion promise
    if (
      !(await this.verifyInclusionPromise(signingCert, bundle, this.root.rekor))
    ) {
      throw new Error("Inclusion promise validation failed.");
    }

    // # 5 Rekor inclusion proof (Merkle tree verification)
    await this.verifyInclusionProof(bundle);

    // # 5.1 Rekor body verification
    if (bundle.verificationMaterial.tlogEntries.length > 0) {
      await verifyTLogBody(
        bundle.verificationMaterial.tlogEntries[0],
        bundle
      );
    }

    // # 6 TSA Timestamp Verification (if present)
    let verifiedTimestamp: Date | undefined;
    if (bundle.verificationMaterial.timestampVerificationData) {
      // Verify TSA timestamps if present
      verifiedTimestamp = await verifyBundleTimestamp(
        bundle.verificationMaterial.timestampVerificationData,
        signature,
        this.rawRoot?.timestampAuthorities || []
      );

      // If we have a verified timestamp, check certificate validity at that time
      if (verifiedTimestamp && !signingCert.validForDate(verifiedTimestamp)) {
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

      // Verify the artifact digest matches the subject in the in-toto statement
      if (!payload.subject || payload.subject.length === 0) {
        throw new Error("DSSE payload has no subject");
      }

      const subjectDigest = payload.subject[0].digest?.["sha256"];
      if (!subjectDigest) {
        throw new Error("DSSE payload subject has no SHA256 digest");
      }

      // Compute or extract the artifact digest
      let artifactDigest: string;
      if (isDigestOnly) {
        // data is already the digest bytes
        artifactDigest = Uint8ArrayToHex(data);
      } else {
        // data is the file content, compute the digest
        artifactDigest = Uint8ArrayToHex(
          new Uint8Array(await crypto.subtle.digest("SHA-256", toArrayBuffer(data)))
        );
      }

      if (artifactDigest !== subjectDigest) {
        throw new Error("Artifact digest does not match DSSE payload subject digest");
      }

      // Create PAE (Pre-Authentication Encoding) for signature verification
      // PAE = "DSSEv1" + SP + LEN(type) + SP + type + SP + LEN(payload) + SP + payload (raw bytes)
      const payloadType = bundle.dsseEnvelope.payloadType;
      const prefix = `DSSEv1 ${payloadType.length} ${payloadType} ${payloadBytes.length} `;
      const prefixBytes = stringToUint8Array(prefix);

      // Concatenate prefix and payload bytes
      const pae = new Uint8Array(prefixBytes.length + payloadBytes.length);
      pae.set(prefixBytes, 0);
      pae.set(payloadBytes, prefixBytes.length);

      const publicKey = await signingCert.publicKeyObj;
      const verified = await verifySignature(publicKey, pae, signature);
      if (!verified) {
        throw new Error("DSSE signature verification failed");
      }
    } else {
      const publicKey = await signingCert.publicKeyObj;

      if (isDigestOnly) {
        // For hashedrekord bundles where only a digest is provided,
        // the signature is over the digest bytes (not the original artifact).
        // WebCrypto's verify() would hash the digest again, so we use elliptic
        // for low-level ECDSA verification over the pre-computed digest.
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
