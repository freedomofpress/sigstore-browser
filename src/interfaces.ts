import { X509Certificate } from "./x509/index.js";

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
}

export interface CTLog {
  logID: Uint8Array;
  publicKey: CryptoKey;
  validFor: {
    start: Date;
    end: Date;
  };
}

export interface RekorKeyInfo {
  publicKey: CryptoKey;
  logId: Uint8Array;
}

export interface CertAuthority {
  certChain: X509Certificate[];
  validFor: {
    start: Date;
    end: Date;
  };
}

export interface Sigstore {
  rekor: RekorKeyInfo | undefined;
  ctlogs: CTLog[];
  certificateAuthorities: CertAuthority[];
  timestampAuthorities: CertAuthority[];
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
