type SigstoreBundleBase = {
  mediaType: string;
  verificationMaterial: VerificationMaterial;
};

export type SigstoreBundle =
  | (SigstoreBundleBase & { messageSignature: MessageSignature; dsseEnvelope?: never })
  | (SigstoreBundleBase & { messageSignature?: never; dsseEnvelope: DSSEEnvelope });

export interface VerificationMaterial {
  certificate?: Certificate;
  x509CertificateChain?: X509CertificateChain;
  tlogEntries: TLogEntry[];
  timestampVerificationData?: TimestampVerificationData;
}

export interface Certificate {
  rawBytes: string; // Base64-encoded certificate bytes
}

export interface X509CertificateChain {
  certificates: Certificate[];
}

export interface TLogEntry {
  logIndex: string;
  logId: LogId;
  kindVersion: KindVersion;
  integratedTime: string | null; // UNIX timestamp (can be null for Rekor v2 bundles)
  inclusionPromise?: InclusionPromise;
  inclusionProof?: InclusionProof;
  canonicalizedBody: string; // Base64-encoded JSON body of the log entry
}

export interface LogId {
  keyId: string; // Base64-encoded key ID
}

export interface KindVersion {
  kind: string;
  version: string;
}

export interface InclusionPromise {
  signedEntryTimestamp: string; // Base64-encoded signature over the entry
}

export interface InclusionProof {
  logIndex: string;
  rootHash: string; // Base64-encoded root hash of the Merkle tree
  treeSize: string; // Number of entries in the Merkle tree
  hashes: string[]; // Base64-encoded sibling hashes in the Merkle tree
  checkpoint: Checkpoint;
}

export interface Checkpoint {
  envelope: string; // Signed envelope from the transparency log
}

export interface MessageSignature {
  messageDigest: MessageDigest;
  signature: string; // Base64-encoded signature over the message digest
}

export interface MessageDigest {
  algorithm: string; // Hashing algorithm, e.g., "SHA2_256"
  digest: string; // Base64-encoded message digest
}

export interface DSSEEnvelope {
  payload: string;
  payloadType: string;
  signatures: DSSESignature[];
}

export interface DSSESignature {
  sig: string;
  keyid?: string;
}

export interface TimestampVerificationData {
  rfc3161Timestamps: RFC3161Timestamp[];
}

export interface RFC3161Timestamp {
  signedTimestamp: string; // Base64-encoded RFC3161 SignedData
}

export interface InTotoStatement {
  _type: string;
  subject: InTotoSubject[];
  predicateType: string;
  predicate: Record<string, unknown>;
}

export interface InTotoSubject {
  name: string;
  digest: Record<string, string>;
}
