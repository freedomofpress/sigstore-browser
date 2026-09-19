import { X509Certificate } from "./x509/index.js";

export function parseValidityPeriod(
  validity: { start?: unknown; end?: unknown } | undefined,
): { start: Date; end: Date } {
  if (
    typeof validity?.start !== "string" ||
    (validity.end !== undefined && typeof validity.end !== "string")
  ) {
    throw new Error("Invalid authority validity period");
  }
  const start = new Date(validity.start);
  const end = validity.end === undefined
    ? new Date(8640000000000000)
    : new Date(validity.end);
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start > end) {
    throw new Error("Invalid authority validity period");
  }
  return { start, end };
}

export enum SigstoreRoots {
  certificateAuthorities = "certificateAuthorities",
  ctlogs = "ctlogs",
  timestampAuthorities = "timestampAuthorities",
  tlogs = "tlogs",
}

export type RawTimestampAuthorities = RawTimestampAuthority[];

export interface TrustedRoot {
  mediaType: string;
  tlogs: RawLogs;
  certificateAuthorities: RawCAs;
  ctlogs: RawLogs;
  timestampAuthorities: RawTimestampAuthorities;
}

export interface RawTimestampAuthority {
  subject: {
    organization: string;
    commonName: string;
  };
  certChain: {
    certificates: {
      rawBytes: string;
    }[];
  };
  validFor: {
    start: string;
    end?: string;
  };
  operator?: string;
}

export interface CTLog {
  logID: Uint8Array;
  publicKey: CryptoKey;
  operator: string;
  validFor: {
    start: Date;
    end: Date;
  };
}

export interface RekorKeyInfo {
  publicKey: CryptoKey;
  logId: Uint8Array;
  hashAlgorithm: string;
  operator: string;
  validFor: {
    start: Date;
    end: Date;
  };
}

export interface CertAuthority {
  certChain: X509Certificate[];
  validFor: {
    start: Date;
    end: Date;
  };
}

export interface Sigstore {
  rekor: RekorKeyInfo[];
  ctlogs: CTLog[];
  certificateAuthorities: CertAuthority[];
}

export interface RawLog {
  baseUrl: string;
  hashAlgorithm: string;
  publicKey: {
    rawBytes: string;
    keyDetails: string;
    validFor: {
      start: string;
      end?: string;
    };
  };
  logId: {
    keyId: string;
  };
  operator?: string;
}

export type RawLogs = RawLog[];

export interface RawCA {
  subject: {
    organization: string;
    commonName: string;
  };
  uri: string;
  certChain: {
    certificates: {
      rawBytes: string;
    }[];
  };
  validFor: {
    start: string;
    end?: string;
  };
}

export type RawCAs = RawCA[];

// Re-export crypto enums from crypto-browser (shared with tuf-browser)
export { KeyTypes, EcdsaTypes, HashAlgorithms } from "@freedomofpress/crypto-browser";
import { HashAlgorithms } from "@freedomofpress/crypto-browser";

// Supported hash algorithms for payload hash validation
// Rekor v1 uses lowercase (sha256), Rekor v2 uses uppercase with underscore (SHA2_256)
const SUPPORTED_HASH_ALGORITHMS: Record<string, string> = {
  "sha256": HashAlgorithms.SHA256,
  "sha384": HashAlgorithms.SHA384,
  "sha512": HashAlgorithms.SHA512,
  "SHA2_256": HashAlgorithms.SHA256,
  "SHA2_384": HashAlgorithms.SHA384,
  "SHA2_512": HashAlgorithms.SHA512,
};

export function getHashAlgorithm(algorithm: string): string {
  const hashAlg = SUPPORTED_HASH_ALGORITHMS[algorithm];
  if (!hashAlg) {
    throw new Error(`Unsupported hash algorithm: ${algorithm}`);
  }
  return hashAlg;
}
