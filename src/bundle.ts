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
// Bound the aggregate encoded data this verifier will decode, parse, or hash.
const MAX_BUNDLE_STRING_CHARS = 16 * 1024 * 1024;
function boundedStrings(): (v: unknown) => v is string {
  let total = 0;
  return (v: unknown): v is string => {
    if (!isStr(v)) return false;
    total += v.length;
    return total <= MAX_BUNDLE_STRING_CHARS;
  };
}
// Protobuf log indices, tree sizes and times are non-negative int64 values.
// Bound the string before BigInt conversion to avoid unbounded arithmetic.
const isInt64 = (v: unknown): v is string =>
  isStr(v) && /^\d{1,19}$/.test(v) && BigInt(v) <= 9223372036854775807n;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null;

function check(cond: unknown, what: string): asserts cond {
  if (!cond) throw new Error(`Invalid bundle: ${what}`);
}

function checkTimestampVerificationData(
  data: unknown,
  isBoundedStr: (v: unknown) => v is string,
): void {
  if (data == null) return;
  check(isObj(data), "timestampVerificationData");
  const ts = data.rfc3161Timestamps;
  check(
    ts === undefined || (Array.isArray(ts) && ts.length <= 32 && ts.every((t: unknown) => isObj(t) && isBoundedStr(t.signedTimestamp))),
    "rfc3161Timestamps",
  );
}

// Lives in verifyBundleTimestamp(), which every caller routes through.
export function assertTimestampVerificationData(data: unknown): void {
  checkTimestampVerificationData(data, boundedStrings());
}

// Structural validation of a parsed bundle, replacing the compile-time-only type with runtime checks.
// Entry count is capped at 32 like sigstore-go does.
export function assertBundle(b: unknown): asserts b is SigstoreBundle {
  const isBoundedStr = boundedStrings();
  check(isObj(b) && isBoundedStr(b.mediaType) && isObj(b.verificationMaterial), "missing mediaType or verificationMaterial");
  const vm = b.verificationMaterial;

  const certs = vm.certificate ? [vm.certificate] : vm.x509CertificateChain?.certificates;
  check(Array.isArray(certs) && certs.length > 0 && certs.length <= 32 && certs.every((c: unknown) => isObj(c) && isBoundedStr(c.rawBytes)), "certificate");

  check(Array.isArray(vm.tlogEntries) && vm.tlogEntries.length > 0 && vm.tlogEntries.length <= 32, "tlogEntries");
  for (const e of vm.tlogEntries) {
    check(isObj(e) && isInt64(e.logIndex) && isBoundedStr(e.logId?.keyId) && isBoundedStr(e.canonicalizedBody), "tlog entry");
    check(isBoundedStr(e.kindVersion?.kind) && isBoundedStr(e.kindVersion?.version), "tlog entry kindVersion");
    check(
      e.integratedTime == null || (isInt64(e.integratedTime) && Number.isFinite(new Date(Number(e.integratedTime) * 1000).getTime())),
      "tlog entry integratedTime",
    );
    // A SET signs the integrated time, so a promise without one is malformed.
    // SET canonicalization uses Number, which must not round the signed log index.
    const set = e.inclusionPromise?.signedEntryTimestamp;
    check(
      e.inclusionPromise === undefined || (isBoundedStr(set) && set !== "" && isInt64(e.integratedTime) && Number.isSafeInteger(Number(e.logIndex))),
      "inclusion promise",
    );
    const p = e.inclusionProof;
    // An int64-sized tree requires at most 63 sibling hashes.
    check(
      p === undefined ||
        (isObj(p) && isInt64(p.logIndex) && isInt64(p.treeSize) && isBoundedStr(p.rootHash) &&
          Array.isArray(p.hashes) && p.hashes.length <= 63 && p.hashes.every(isBoundedStr) && isBoundedStr(p.checkpoint?.envelope)),
      "inclusion proof",
    );
  }

  checkTimestampVerificationData(vm.timestampVerificationData, isBoundedStr);

  const { messageSignature: ms, dsseEnvelope: env } = b;
  check((ms === undefined) !== (env === undefined), "exactly one of messageSignature or dsseEnvelope");
  if (ms !== undefined) {
    check(isObj(ms) && isBoundedStr(ms.signature) && isBoundedStr(ms.messageDigest?.algorithm) && isBoundedStr(ms.messageDigest?.digest), "messageSignature");
  } else {
    check(isObj(env) && isBoundedStr(env.payload) && isBoundedStr(env.payloadType), "dsseEnvelope");
    check(Array.isArray(env.signatures) && env.signatures.length === 1 && isBoundedStr(env.signatures[0]?.sig), "dsseEnvelope must have exactly one signature");
  }
}
