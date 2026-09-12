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

const isStr = (v: unknown): v is string => typeof v === "string";
const isDigits = (v: unknown): boolean => isStr(v) && /^\d+$/.test(v);
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null;

function check(cond: unknown, what: string): asserts cond {
  if (!cond) throw new Error(`Invalid bundle: ${what}`);
}

// Structural validation of a parsed bundle, replacing the compile-time-only type with runtime checks.
export function assertBundle(b: unknown): asserts b is SigstoreBundle {
  check(isObj(b) && isStr(b.mediaType) && isObj(b.verificationMaterial), "missing mediaType or verificationMaterial");
  const vm = b.verificationMaterial;

  const certs = vm.certificate ? [vm.certificate] : vm.x509CertificateChain?.certificates;
  check(Array.isArray(certs) && certs.length > 0 && certs.every((c: unknown) => isObj(c) && isStr(c.rawBytes)), "certificate");

  check(Array.isArray(vm.tlogEntries) && vm.tlogEntries.length > 0, "tlogEntries");
  for (const e of vm.tlogEntries) {
    check(isObj(e) && isDigits(e.logIndex) && isStr(e.logId?.keyId) && isStr(e.canonicalizedBody), "tlog entry");
    check(isStr(e.kindVersion?.kind) && isStr(e.kindVersion?.version), "tlog entry kindVersion");
    check(e.integratedTime == null || isDigits(e.integratedTime), "tlog entry integratedTime");
    check(e.inclusionPromise === undefined || (isStr(e.inclusionPromise?.signedEntryTimestamp) && e.inclusionPromise.signedEntryTimestamp !== ""), "inclusion promise");
    const p = e.inclusionProof;
    check(
      p === undefined ||
        (isObj(p) && isDigits(p.logIndex) && isDigits(p.treeSize) && isStr(p.rootHash) &&
          Array.isArray(p.hashes) && p.hashes.every(isStr) && isStr(p.checkpoint?.envelope)),
      "inclusion proof",
    );
  }

  const ts = vm.timestampVerificationData?.rfc3161Timestamps;
  check(ts === undefined || (Array.isArray(ts) && ts.every((t: unknown) => isObj(t) && isStr(t.signedTimestamp))), "rfc3161Timestamps");

  const { messageSignature: ms, dsseEnvelope: env } = b;
  check((ms === undefined) !== (env === undefined), "exactly one of messageSignature or dsseEnvelope");
  if (ms !== undefined) {
    check(isObj(ms) && isStr(ms.signature) && isStr(ms.messageDigest?.algorithm) && isStr(ms.messageDigest?.digest), "messageSignature");
  } else {
    check(isObj(env) && isStr(env.payload) && isStr(env.payloadType), "dsseEnvelope");
    check(Array.isArray(env.signatures) && env.signatures.length === 1 && isStr(env.signatures[0]?.sig), "dsseEnvelope must have exactly one signature");
  }
}
