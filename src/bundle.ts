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
  rfc3161Timestamps?: RFC3161Timestamp[];
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

// Only the canonical protobuf JSON encoding is accepted: lowerCamelCase names, int64 as decimal
// strings, bytes as padded standard base64, no unknown fields. protojson-based verifiers accept
// more, but pinning the canonical form keeps every verifier's view of a bundle identical.
const isCanonicalBase64 = (s: string): boolean => {
  try { return btoa(atob(s)) === s; } catch { return false; }
};

// Protobuf log indices, tree sizes and times are non-negative int64 values.
// Bound the string before BigInt conversion to avoid unbounded arithmetic.
const isInt64 = (v: unknown): v is string =>
  isStr(v) && /^\d{1,19}$/.test(v) && BigInt(v) <= 9223372036854775807n;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const isObj = (v: unknown): v is Record<string, any> => typeof v === "object" && v !== null;

function check(cond: unknown, what: string): asserts cond {
  if (!cond) throw new Error(`Invalid bundle: ${what}`);
}

// Asserts an object whose keys are all fields the protobuf message defines (sigstore/protobuf-specs names).
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function fields(v: unknown, where: string, allowed: string[]): Record<string, any> {
  check(isObj(v), where);
  for (const k of Object.keys(v)) check(allowed.includes(k), `unknown field "${k}" in ${where}`);
  return v;
}

function checkTimestampVerificationData(
  data: unknown,
  isBoundedStr: (v: unknown) => v is string,
): asserts data is TimestampVerificationData | undefined {
  if (data == null) return;
  const ts = fields(data, "timestampVerificationData", ["rfc3161Timestamps"]).rfc3161Timestamps;
  check(ts === undefined || (Array.isArray(ts) && ts.length <= 32), "rfc3161Timestamps");
  for (const t of ts ?? []) {
    const stamp = fields(t, "rfc3161Timestamps", ["signedTimestamp"]).signedTimestamp;
    check(isBoundedStr(stamp) && isCanonicalBase64(stamp), "rfc3161Timestamps");
  }
}

// Lives in verifyBundleTimestamp(), which every caller routes through.
export function assertTimestampVerificationData(data: unknown): asserts data is TimestampVerificationData | undefined {
  checkTimestampVerificationData(data, boundedStrings());
}

// Structural validation of a parsed bundle, replacing the compile-time-only type with runtime checks.
// Entry count is capped at 32 like sigstore-go does.
export function assertBundle(b: unknown): asserts b is SigstoreBundle {
  const isBoundedStr = boundedStrings();
  const isB64 = (v: unknown): v is string => isBoundedStr(v) && isCanonicalBase64(v);
  const root = fields(b, "bundle", ["mediaType", "verificationMaterial", "messageSignature", "dsseEnvelope"]);
  check(isBoundedStr(root.mediaType) && isObj(root.verificationMaterial), "missing mediaType or verificationMaterial");
  const vm = fields(root.verificationMaterial, "verificationMaterial", ["publicKey", "x509CertificateChain", "certificate", "tlogEntries", "timestampVerificationData"]);
  const certs = vm.certificate ? [vm.certificate] : fields(vm.x509CertificateChain ?? {}, "x509CertificateChain", ["certificates"]).certificates;
  check(Array.isArray(certs) && certs.length > 0 && certs.length <= 32, "certificate");
  for (const c of certs) check(isB64(fields(c, "certificate", ["rawBytes"]).rawBytes), "certificate");
  check(Array.isArray(vm.tlogEntries) && vm.tlogEntries.length > 0 && vm.tlogEntries.length <= 32, "tlogEntries");
  for (const e of vm.tlogEntries) {
    fields(e, "tlog entry", ["logIndex", "logId", "kindVersion", "integratedTime", "inclusionPromise", "inclusionProof", "canonicalizedBody"]);
    check(isInt64(e.logIndex) && isB64(fields(e.logId, "logId", ["keyId"]).keyId) && isB64(e.canonicalizedBody), "tlog entry");
    const kv = fields(e.kindVersion, "kindVersion", ["kind", "version"]);
    check(isBoundedStr(kv.kind) && isBoundedStr(kv.version), "tlog entry kindVersion");
    check(
      e.integratedTime == null || (isInt64(e.integratedTime) && Number.isFinite(new Date(Number(e.integratedTime) * 1000).getTime())),
      "tlog entry integratedTime",
    );
    // A SET signs the integrated time, so a promise without one is malformed.
    // SET canonicalization uses Number, which must not round the signed log index.
    if (e.inclusionPromise !== undefined) {
      const set = fields(e.inclusionPromise, "inclusionPromise", ["signedEntryTimestamp"]).signedEntryTimestamp;
      check(isB64(set) && set !== "" && isInt64(e.integratedTime) && Number.isSafeInteger(Number(e.logIndex)), "inclusion promise");
    }
    // An int64-sized tree requires at most 63 sibling hashes.
    if (e.inclusionProof !== undefined) {
      const p = fields(e.inclusionProof, "inclusionProof", ["logIndex", "rootHash", "treeSize", "hashes", "checkpoint"]);
      check(isInt64(p.logIndex) && isInt64(p.treeSize) && isB64(p.rootHash) && Array.isArray(p.hashes) && p.hashes.length <= 63 && p.hashes.every(isB64), "inclusion proof");
      check(isBoundedStr(fields(p.checkpoint, "checkpoint", ["envelope"]).envelope), "inclusion proof");
    }
  }
  checkTimestampVerificationData(vm.timestampVerificationData, isBoundedStr);
  const { messageSignature: ms, dsseEnvelope: env } = root;
  check((ms === undefined) !== (env === undefined), "exactly one of messageSignature or dsseEnvelope");
  if (ms !== undefined) {
    fields(ms, "messageSignature", ["messageDigest", "signature"]);
    const md = fields(ms.messageDigest, "messageDigest", ["algorithm", "digest"]);
    check(isB64(ms.signature) && isBoundedStr(md.algorithm) && isB64(md.digest), "messageSignature");
  } else {
    fields(env, "dsseEnvelope", ["payload", "payloadType", "signatures"]);
    check(isB64(env.payload) && isBoundedStr(env.payloadType), "dsseEnvelope");
    check(Array.isArray(env.signatures) && env.signatures.length === 1, "dsseEnvelope must have exactly one signature");
    const sig = fields(env.signatures[0], "dsseEnvelope signature", ["sig", "keyid"]);
    check(isB64(sig.sig) && (sig.keyid === undefined || isBoundedStr(sig.keyid)), "dsseEnvelope must have exactly one signature");
  }
}

// Rejects JSON text with a repeated key in any object: JSON.parse keeps the last occurrence and
// other parsers the first, a classic verifier differential. The text must already be valid JSON.
export function assertNoDuplicateKeys(text: string): void {
  const scopes: (Set<string> | null)[] = []; // one key set per open object, null for arrays
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === "{") scopes.push(new Set());
    else if (c === "[") scopes.push(null);
    else if (c === "}" || c === "]") scopes.pop();
    else if (c === "\"") {
      const start = i++;
      while (text[i] !== "\"") i += text[i] === "\\" ? 2 : 1;
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j])) j++;
      const keys = scopes[scopes.length - 1];
      if (keys && text[j] === ":") {
        const key = JSON.parse(text.slice(start, i + 1)) as string;
        check(!keys.has(key), `duplicate key ${JSON.stringify(key)}`);
        keys.add(key);
      }
    }
  }
}

// Parses bundle JSON text. Prefer this over JSON.parse + assertBundle: it also rejects duplicate keys.
export function parseBundle(text: string): SigstoreBundle {
  check(text.length <= MAX_BUNDLE_STRING_CHARS, "too large");
  const bundle: unknown = JSON.parse(text);
  assertNoDuplicateKeys(text);
  assertBundle(bundle);
  return bundle;
}
