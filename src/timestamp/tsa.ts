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

import { RFC3161Timestamp } from "../rfc3161/index.js";
import { X509Certificate, CertificateChainVerifier } from "../x509/index.js";
import { bufferEqual } from "../crypto.js";
import { base64ToUint8Array } from "../encoding.js";
import type { RawTimestampAuthority } from "../interfaces.js";

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

  if (process.env.DEBUG_SIGSTORE) {
    console.error(`Valid authorities after date filter: ${validAuthorities.length}`);
  }

  // Filter for CAs which match serial and issuer embedded in the timestamp
  validAuthorities = filterCAsBySerialAndIssuer(validAuthorities, {
    serialNumber: timestamp.signerSerialNumber,
    issuer: timestamp.signerIssuer,
  });

  if (process.env.DEBUG_SIGSTORE) {
    console.error(`Valid authorities after serial/issuer filter: ${validAuthorities.length}`);
  }

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
  if (process.env.DEBUG_SIGSTORE) {
    console.error(`Filtering by serial: ${Buffer.from(criteria.serialNumber).toString('hex')}`);
    console.error(`Filtering by issuer length: ${criteria.issuer.length}`);
  }

  return timestampAuthorities.filter(ca => {
    if (!ca.certChain || ca.certChain.certificates.length === 0) {
      return false;
    }

    const leafCert = X509Certificate.parse(
      base64ToUint8Array(ca.certChain.certificates[0].rawBytes)
    );

    if (process.env.DEBUG_SIGSTORE) {
      console.error(`CA cert[0] serial: ${Buffer.from(leafCert.serialNumber).toString('hex')}`);
      console.error(`CA cert[0] issuer length: ${leafCert.issuer.length}`);
    }

    const matches = bufferEqual(leafCert.serialNumber, criteria.serialNumber) &&
           bufferEqual(leafCert.issuer, criteria.issuer);

    if (matches && process.env.DEBUG_SIGSTORE) {
      console.error(`Found matching leaf certificate`);
    }

    return matches;
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

  if (process.env.DEBUG_SIGSTORE) {
    console.error(`Timestamp signing cert algorithm: ${publicKey.algorithm.name}`);
  }

  try {
    await timestamp.verify(data, publicKey);
  } catch (e) {
    if (process.env.DEBUG_SIGSTORE) {
      console.error(`Timestamp verify failed: ${e}`);
    }
    throw e;
  }
}

/**
 * Extracts the verified timestamp from a bundle's timestamp verification data
 *
 * New functionality for Sigstore bundle integration (not in sigstore-js reference)
 *
 * @param timestampData - The timestamp verification data from the bundle
 * @param signature - The signature being verified
 * @param timestampAuthorities - List of trusted timestamp authorities
 * @returns The verified signing time, or undefined if no timestamp
 */
export async function verifyBundleTimestamp(
  timestampData: any,
  signature: Uint8Array,
  timestampAuthorities: RawTimestampAuthority[]
): Promise<Date | undefined> {
  if (!timestampData?.rfc3161Timestamps?.length) {
    return undefined;
  }

  if (process.env.DEBUG_SIGSTORE) {
    console.error(`Processing ${timestampData.rfc3161Timestamps.length} RFC3161 timestamps`);
    console.error(`Timestamp authorities: ${timestampAuthorities.length}`);
  }

  // Check for duplicate timestamps
  const seenTimestamps = new Set<string>();
  for (const tsData of timestampData.rfc3161Timestamps) {
    if (seenTimestamps.has(tsData.signedTimestamp)) {
      throw new Error("Duplicate TSA timestamp detected");
    }
    seenTimestamps.add(tsData.signedTimestamp);
  }

  // Process each RFC3161 timestamp
  const errors: string[] = [];
  for (const tsData of timestampData.rfc3161Timestamps) {
    try {
      // Decode the base64-encoded timestamp
      const timestampBytes = base64ToUint8Array(tsData.signedTimestamp);
      const timestamp = RFC3161Timestamp.parse(timestampBytes);

      if (process.env.DEBUG_SIGSTORE) {
        console.error(`Timestamp signing time: ${timestamp.signingTime}`);
      }

      const signingTime = await verifyRFC3161Timestamp(
        timestamp,
        signature,
        timestampAuthorities
      );
      return signingTime;
    } catch (e) {
      // Continue to next timestamp if this one fails
      if (process.env.DEBUG_SIGSTORE) {
        console.error(`Timestamp verification failed: ${e}`);
      }
      errors.push(e instanceof Error ? e.message : String(e));
      continue;
    }
  }

  throw new Error(`No valid RFC3161 timestamps found. Errors: ${errors.join(', ')}`);
}