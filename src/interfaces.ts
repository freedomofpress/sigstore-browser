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
