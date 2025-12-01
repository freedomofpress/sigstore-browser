/*
 * TSA (Time-Stamping Authority) timestamp verification
 *
 * Based on sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/timestamp/tsa.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: uses Uint8Array instead of Buffer for binary data
 * - Uses Web Crypto API for all cryptographic operations
 * - Integrates with existing RFC3161 timestamp implementation
 * - Uses CertificateChainVerifier for full X.509 path validation
 * - Implements filterCertAuthorities inline (from sigstore-js/packages/verify/src/trust/filter.ts)
 * - Adds verifyBundleTimestamp for Sigstore bundle integration (new functionality)
 */

import { base64ToUint8Array, uint8ArrayEqual } from "@freedomofpress/crypto-browser";
import { CertificateChainVerifier, X509Certificate } from "../x509/index.js";
import { RawTimestampAuthority } from "../interfaces.js";
import { RFC3161Timestamp } from "../rfc3161/index.js";

/**
 * Verifies an RFC3161 timestamp against a set of timestamp authorities
 *
 * @param timestamp - The RFC3161 timestamp to verify
 * @param data - The data that was timestamped
 * @param timestampAuthorities - List of trusted timestamp authorities
 * @returns The verified signing time
 * @throws Error if timestamp cannot be verified
 */
export async function verifyRFC3161Timestamp(
  timestamp: RFC3161Timestamp,
  data: Uint8Array,
  timestampAuthorities: RawTimestampAuthority[]
): Promise<Date> {
  const signingTime = timestamp.signingTime;

  // Filter for CAs which were valid at the time of signing
  let validAuthorities = filterCertAuthorities(
    timestampAuthorities,
    signingTime
  );

  // Filter for CAs which match serial and issuer embedded in the timestamp
  validAuthorities = filterCAsBySerialAndIssuer(validAuthorities, {
    serialNumber: timestamp.signerSerialNumber,
    issuer: timestamp.signerIssuer,
  });

  // Check that we can verify the timestamp with AT LEAST ONE of the remaining CAs
  const verificationResults = await Promise.allSettled(
    validAuthorities.map(ca => verifyTimestampForCA(timestamp, data, ca))
  );

  const verified = verificationResults.some(
    result => result.status === "fulfilled"
  );

  if (!verified) {
    const errors = verificationResults
      .filter(r => r.status === "rejected")
      .map(r => (r as PromiseRejectedResult).reason?.message || 'Unknown error');
    throw new Error(`Timestamp could not be verified against any trusted authority. Errors: ${errors.join(', ')}`);
  }

  return signingTime;
}

/**
 * Filters certificate authorities to those valid at a specific time
 *
 * Adapted from sigstore-js/packages/verify/src/trust/filter.ts
 */
function filterCertAuthorities(
  authorities: RawTimestampAuthority[],
  validAt: Date
): RawTimestampAuthority[] {
  return authorities.filter(ca => {
    if (ca.validFor) {
      const start = ca.validFor.start ? new Date(ca.validFor.start) : null;
      const end = ca.validFor.end ? new Date(ca.validFor.end) : null;

      if (start && validAt < start) {
        return false;
      }
      if (end && validAt > end) {
        return false;
      }
    }
    return true;
  });
}

/**
 * Filters certificate authorities by serial number and issuer
 *
 * Only checks the LEAF certificate (TSA signing cert), not the entire chain.
 * This matches the sigstore-js reference implementation.
 */
function filterCAsBySerialAndIssuer(
  timestampAuthorities: RawTimestampAuthority[],
  criteria: { serialNumber: Uint8Array; issuer: Uint8Array }
): RawTimestampAuthority[] {
  return timestampAuthorities.filter(ca => {
    if (!ca.certChain || ca.certChain.certificates.length === 0) {
      return false;
    }

    const leafCert = X509Certificate.parse(
      base64ToUint8Array(ca.certChain.certificates[0].rawBytes)
    );

    return uint8ArrayEqual(leafCert.serialNumber, criteria.serialNumber) &&
           uint8ArrayEqual(leafCert.issuer, criteria.issuer);
  });
}

/**
 * Verifies a timestamp against a specific certificate authority
 */
async function verifyTimestampForCA(
  timestamp: RFC3161Timestamp,
  data: Uint8Array,
  ca: RawTimestampAuthority
): Promise<void> {
  if (!ca.certChain || ca.certChain.certificates.length === 0) {
    throw new Error("Certificate authority missing certificate chain");
  }

  const leafCert = X509Certificate.parse(
    base64ToUint8Array(ca.certChain.certificates[0].rawBytes)
  );
  const signingTime = timestamp.signingTime;

  const trustedCerts = ca.certChain.certificates
    .slice(1)
    .map(cert => X509Certificate.parse(base64ToUint8Array(cert.rawBytes)));

  try {
    const verifier = new CertificateChainVerifier({
      untrustedCert: leafCert,
      trustedCerts: trustedCerts,
      timestamp: signingTime,
    });
    await verifier.verify();
  } catch (e) {
    throw new Error(`TSA certificate chain verification failed: ${e instanceof Error ? e.message : String(e)}`);
  }

  const publicKey = await leafCert.publicKeyObj;

  await timestamp.verify(data, publicKey);
}

/**
 * Verifies all timestamps in a bundle's timestamp verification data
 *
 * Matches sigstore-js behavior: all timestamps must successfully verify.
 * Reference: https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/verifier.ts#L64-L108
 *
 * @param timestampData - The timestamp verification data from the bundle
 * @param signature - The signature being verified
 * @param timestampAuthorities - List of trusted timestamp authorities
 * @returns Array of verified signing times (empty if no timestamps present)
 * @throws Error if any timestamp fails verification or duplicates are found
 */
export async function verifyBundleTimestamp(
  timestampData: any,
  signature: Uint8Array,
  timestampAuthorities: RawTimestampAuthority[]
): Promise<Date[]> {
  if (!timestampData?.rfc3161Timestamps?.length) {
    return [];
  }

  // Verify ALL timestamps - each must succeed (matches sigstore-js behavior)
  // Collect verification results for duplicate checking after verification
  // Reference: https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/verifier.ts#L86-L92
  const verifiedResults: Array<{ signingTime: Date; signerSerialNumber: string }> = [];

  for (const tsData of timestampData.rfc3161Timestamps) {
    // Decode the base64-encoded timestamp
    const timestampBytes = base64ToUint8Array(tsData.signedTimestamp);
    const timestamp = RFC3161Timestamp.parse(timestampBytes);

    const signingTime = await verifyRFC3161Timestamp(
      timestamp,
      signature,
      timestampAuthorities
    );

    verifiedResults.push({
      signingTime,
      signerSerialNumber: Array.from(timestamp.signerSerialNumber).join(','),
    });
  }

  // Check for duplicate timestamps using deep equality on parsed values
  // sigstore-js uses isDeepStrictEqual on {type, logID, timestamp} objects
  for (let i = 0; i < verifiedResults.length; i++) {
    for (let j = i + 1; j < verifiedResults.length; j++) {
      if (
        verifiedResults[i].signingTime.getTime() === verifiedResults[j].signingTime.getTime() &&
        verifiedResults[i].signerSerialNumber === verifiedResults[j].signerSerialNumber
      ) {
        throw new Error("Duplicate TSA timestamp detected");
      }
    }
  }

  return verifiedResults.map(r => r.signingTime);
}