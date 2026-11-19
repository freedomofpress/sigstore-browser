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

import { base64ToUint8Array, uint8ArrayEqual, Uint8ArrayToHex } from "@freedomofpress/crypto-browser";

import { assertTimestampVerificationData } from "../bundle.js";
import { errorMessage, fail, VerificationError } from "../errors.js";
import { parseValidityPeriod, RawTimestampAuthority } from "../interfaces.js";
import { RFC3161TimestampVerificationError } from "../rfc3161/error.js";
import { RFC3161Timestamp } from "../rfc3161/index.js";
import { CertificateChainVerifier, X509Certificate } from "../x509/index.js";

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
  return (await verifyTimestamp(timestamp, data, timestampAuthorities)).signingTime;
}

export interface VerifiedTimestamp {
  signingTime: Date;
  // Empty means unknown, which cannot add independence to named operators.
  operator: string;
}

async function verifyTimestamp(
  timestamp: RFC3161Timestamp,
  data: Uint8Array,
  timestampAuthorities: RawTimestampAuthority[]
): Promise<VerifiedTimestamp> {
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

  const verified = verificationResults.findIndex(
    result => result.status === "fulfilled"
  );

  if (verified < 0) {
    const errors = verificationResults
      .filter(r => r.status === "rejected")
      .map(r => (r as PromiseRejectedResult).reason?.message || 'Unknown error');
    throw new Error(`Timestamp could not be verified against any trusted authority. Errors: ${errors.join(', ')}`);
  }

  const ca = validAuthorities[verified];
  return { signingTime, operator: ca.operator || "" };
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
    const { start, end } = parseValidityPeriod(ca.validFor);
    return start <= validAt && validAt <= end;
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

  const publicKey = await verifiedAuthorityKey(ca, timestamp.signingTime);

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
 * @returns The verified signing times and their operators (empty if no timestamps present)
 * @throws Error if any timestamp fails verification or duplicates are found
 */
export async function verifyBundleTimestamp(
  timestampData: unknown,
  signature: Uint8Array,
  timestampAuthorities: RawTimestampAuthority[]
): Promise<VerifiedTimestamp[]> {
  assertTimestampVerificationData(timestampData);
  if (!timestampData?.rfc3161Timestamps?.length) {
    return [];
  }

  // Verify ALL timestamps - each must succeed (matches sigstore-js behavior)
  // Collect verification results for duplicate checking after verification
  // Reference: https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/verifier.ts#L86-L92
  const verifiedResults: Array<VerifiedTimestamp & { signerSerialNumber: string }> = [];

  for (const tsData of timestampData.rfc3161Timestamps) {
    // Decode the base64-encoded timestamp
    const timestampBytes = base64ToUint8Array(tsData.signedTimestamp);
    const timestamp = RFC3161Timestamp.parse(timestampBytes);

    verifiedResults.push({
      ...(await verifyTimestamp(timestamp, signature, timestampAuthorities)),
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

  return verifiedResults;
}

/**
 * Verifies every RFC 3161 timestamp in a bundle over `signature`, like verifyBundleTimestamp, but
 * reports why one fails with a VerificationError code: "timestamp-malformed",
 * "timestamp-untrusted-authority" (no trusted authority, valid at the timestamp's time, issued it),
 * "timestamp-message-mismatch" (it covers another signature), "timestamp-signature-invalid" or
 * "timestamp-duplicate". Only certificates from the trusted root are used, never ones in the token.
 */
export async function verifyBundleTimestampForSignature(
  timestampData: unknown,
  signature: Uint8Array,
  timestampAuthorities: RawTimestampAuthority[]
): Promise<VerifiedTimestamp[]> {
  assertTimestampVerificationData(timestampData);
  const verified: VerifiedTimestamp[] = [];
  const seen = new Set<string>();

  for (const tsData of timestampData?.rfc3161Timestamps ?? []) {
    const timestamp = parseTimestamp(tsData.signedTimestamp);
    const signingTime = timestamp.signingTime;
    const validAuthorities = filterCertAuthorities(timestampAuthorities, signingTime);
    const candidates = filterCAsBySerialAndIssuer(validAuthorities, {
      serialNumber: timestamp.signerSerialNumber,
      issuer: timestamp.signerIssuer,
    });
    const authority = await findIssuingAuthority(timestamp, signature, candidates, signingTime);

    const identity = timestampIdentity(signingTime, timestamp.signerSerialNumber);
    if (seen.has(identity)) {
      fail("timestamp-duplicate", "Duplicate TSA timestamp detected");
    }
    seen.add(identity);
    const operator = authority.operator || "";
    verified.push({ signingTime, operator });
  }

  return verified;
}

// Duplicate timestamps have the same signing time and signer serial bytes; hex preserves byte equality.
function timestampIdentity(signingTime: Date, serial: Uint8Array): string {
  const milliseconds = signingTime.getTime();
  const serialKey = Uint8ArrayToHex(serial);
  return `${milliseconds}:${serialKey}`;
}

function parseTimestamp(signedTimestamp: string): RFC3161Timestamp {
  try {
    const bytes = base64ToUint8Array(signedTimestamp);
    const timestamp = RFC3161Timestamp.parse(bytes);
    // Read the required fields here so malformed timestamps keep their reason code.
    void timestamp.signerSerialNumber;
    void timestamp.signerIssuer;
    void timestamp.signingTime;
    return timestamp;
  } catch (error) {
    const message = errorMessage(error);
    fail("timestamp-malformed", `Malformed RFC 3161 timestamp: ${message}`);
  }
}

// Prefer a timestamp verification failure over an untrusted certificate chain.
async function findIssuingAuthority(
  timestamp: RFC3161Timestamp,
  signature: Uint8Array,
  candidates: RawTimestampAuthority[],
  signingTime: Date,
): Promise<RawTimestampAuthority> {
  let failure: VerificationError | undefined;
  for (const authority of candidates) {
    let publicKey: CryptoKey;
    try {
      publicKey = await verifiedAuthorityKey(authority, signingTime);
    } catch (error) {
      const message = errorMessage(error);
      failure ??= new VerificationError("timestamp-untrusted-authority", message);
      continue;
    }

    try {
      await timestamp.verify(signature, publicKey);
      return authority;
    } catch (error) {
      const message = `RFC 3161 timestamp: ${errorMessage(error)}`;
      if (error instanceof RFC3161TimestampVerificationError) {
        failure = new VerificationError(error.code, message);
      } else {
        failure = new VerificationError("timestamp-malformed", message);
      }
    }
  }

  if (failure) {
    throw failure;
  }
  throw new VerificationError(
    "timestamp-untrusted-authority",
    "RFC 3161 timestamp was not issued by a timestamp authority in the trusted root",
  );
}

// The authority's signing key after its trusted-root chain verifies at the signing time.
async function verifiedAuthorityKey(authority: RawTimestampAuthority, signingTime: Date): Promise<CryptoKey> {
  const certificates = authority.certChain.certificates.map((certificate) => {
    const bytes = base64ToUint8Array(certificate.rawBytes);
    return X509Certificate.parse(bytes);
  });
  const [leaf, ...trustedCerts] = certificates;
  const verifier = new CertificateChainVerifier({
    untrustedCert: leaf,
    trustedCerts,
    timestamp: signingTime,
  });
  try {
    await verifier.verify();
  } catch (error) {
    const message = errorMessage(error);
    throw new Error(`TSA certificate chain verification failed: ${message}`);
  }
  return leaf.publicKeyObj;
}
