/*
Checkpoint verification for transparency log entries.

Adapted from sigstore-js for browser compatibility:
https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/timestamp/checkpoint.ts

Key differences:
- Uses Uint8Array instead of Buffer
- Uses Web Crypto API instead of Node.js crypto module
- Manual handling of ED25519 (raw) vs ECDSA (DER) signature formats
- Inline key import from raw bytes

Additional functionality not in reference:
- filterTLogsByDate() - inlined from sigstore-js/packages/verify/src/trust/filter.ts
- importTLogKey() - new browser-compatible key import with multiple format support
- Special handling for Rekor v2 bundles without integratedTime

Follows the signed note format specification:
https://github.com/transparency-dev/formats/blob/main/log/README.md
*/

import { base64ToUint8Array, stringToUint8Array, toArrayBuffer, uint8ArrayEqual, Uint8ArrayToHex } from "../encoding.js";
import { importKey, verifySignature } from "../crypto.js";
import type { TLogEntry } from "../bundle.js";
import type { RawLogs } from "../interfaces.js";

// Signed note format per https://github.com/transparency-dev/formats
// Body is separated from signatures by a blank line
const CHECKPOINT_SEPARATOR = "\n\n";
// Signature lines format: "— <identity> <base64(key_hint+signature)>\n"
// \u2014 is the em-dash character (—)
const SIGNATURE_REGEX = /\u2014 (\S+) (\S+)\n/g;

export interface TLogSignature {
  name: string;
  keyHint: Uint8Array;
  signature: Uint8Array;
}

// Signed checkpoint note with cryptographic signatures
export class SignedNote {
  readonly note: string;
  readonly signatures: TLogSignature[];

  constructor(note: string, signatures: TLogSignature[]) {
    this.note = note;
    this.signatures = signatures;
  }

  static fromString(envelope: string): SignedNote {
    if (!envelope.includes(CHECKPOINT_SEPARATOR)) {
      throw new Error("Missing checkpoint separator");
    }

    // Split body from signature lines at blank line
    const split = envelope.indexOf(CHECKPOINT_SEPARATOR);
    const header = envelope.slice(0, split + 1);
    const data = envelope.slice(split + CHECKPOINT_SEPARATOR.length);

    // Parse signature lines: "— <identity> <base64(key_hint+signature)>\n"
    const matches = data.matchAll(SIGNATURE_REGEX);

    const signatures: TLogSignature[] = [];
    for (const match of matches) {
      const [, name, signature] = match;
      const sigBytes = base64ToUint8Array(signature);

      // First 4 bytes are key hint (SHA256 hash prefix), rest is signature
      if (sigBytes.length < 5) {
        throw new Error("Malformed checkpoint signature");
      }

      signatures.push({
        name,
        keyHint: sigBytes.subarray(0, 4),
        signature: sigBytes.subarray(4),
      });
    }

    if (signatures.length === 0) {
      throw new Error("No signatures found in checkpoint");
    }

    return new SignedNote(header, signatures);
  }
}

// Parsed checkpoint containing tree state (origin, size, root hash)
export class LogCheckpoint {
  readonly origin: string;
  readonly logSize: bigint;
  readonly logHash: Uint8Array;
  readonly rest: string[];

  constructor(
    origin: string,
    logSize: bigint,
    logHash: Uint8Array,
    rest: string[]
  ) {
    this.origin = origin;
    this.logSize = logSize;
    this.logHash = logHash;
    this.rest = rest;
  }

  static fromString(note: string): LogCheckpoint {
    const lines = note.trimEnd().split("\n");

    if (lines.length < 3) {
      throw new Error("Too few lines in checkpoint header");
    }

    const origin = lines[0];
    const logSize = BigInt(lines[1]);
    const rootHash = base64ToUint8Array(lines[2]);
    const rest = lines.slice(3);

    return new LogCheckpoint(origin, logSize, rootHash, rest);
  }
}

// Verifies checkpoint signature and ensures root hash matches inclusion proof
export async function verifyCheckpoint(
  entry: TLogEntry,
  tlogs: RawLogs
): Promise<void> {
  if (!entry.inclusionProof?.checkpoint) {
    throw new Error("Missing checkpoint in inclusion proof");
  }

  // Filter by log ID first (matches entry's log ID)
  const entryLogId = base64ToUint8Array(entry.logId.keyId);
  const matchingTLogs = tlogs.filter((tlog) => {
    const tlogId = base64ToUint8Array(tlog.logId.keyId);
    return uint8ArrayEqual(tlogId, entryLogId);
  });

  // Then filter by date if integratedTime is available
  // For Rekor v2 bundles, integratedTime may be null, so we skip date filtering
  const validTLogs = entry.integratedTime
    ? filterTLogsByDate(matchingTLogs, new Date(Number(entry.integratedTime) * 1000))
    : matchingTLogs;

  const inclusionProof = entry.inclusionProof;
  const signedNote = SignedNote.fromString(inclusionProof.checkpoint.envelope);
  const checkpoint = LogCheckpoint.fromString(signedNote.note);

  if (!(await verifySignedNote(signedNote, validTLogs))) {
    throw new Error("Invalid checkpoint signature");
  }

  const rootHash = base64ToUint8Array(inclusionProof.rootHash);
  if (!uint8ArrayEqual(checkpoint.logHash, rootHash)) {
    throw new Error("Root hash mismatch between checkpoint and inclusion proof");
  }
}

// Verifies checkpoint signatures using trusted TLog keys
async function verifySignedNote(
  signedNote: SignedNote,
  tlogs: RawLogs
): Promise<boolean> {
  const data = stringToUint8Array(signedNote.note);

  // We need at least one valid signature from a known TLog
  let hasValidSignature = false;

  for (const signature of signedNote.signatures) {
    // Match signature to TLog using key hint (first 4 bytes of key ID)
    const tlog = tlogs.find((tlog) => {
      const logId = base64ToUint8Array(tlog.logId.keyId);
      return uint8ArrayEqual(logId.subarray(0, 4), signature.keyHint);
    });

    if (!tlog) {
      // Skip unknown signatures (e.g., from witnesses we don't know about)
      continue;
    }

    const publicKey = await importTLogKey(tlog);

    // Both ED25519 and ECDSA verification are now handled by verifySignature
    // ED25519 signatures are raw (64 bytes), ECDSA signatures are DER-encoded
    const verified = await verifySignature(
      publicKey,
      data,
      signature.signature,
      tlog.hashAlgorithm
    );

    if (verified) {
      hasValidSignature = true;
    }
  }

  return hasValidSignature;
}


// Inlined from sigstore-js/packages/verify/src/trust/filter.ts
function filterTLogsByDate(tlogs: RawLogs, targetDate: Date): RawLogs {
  return tlogs.filter((tlog) => {
    const start = new Date(tlog.publicKey.validFor.start);
    const end = tlog.publicKey.validFor.end
      ? new Date(tlog.publicKey.validFor.end)
      : null;

    return targetDate >= start && (!end || targetDate <= end);
  });
}

// Browser-compatible key import supporting multiple formats (not in sigstore-js reference)
async function importTLogKey(tlog: RawLogs[0]): Promise<CryptoKey> {
  // Parse keyDetails to extract key type and scheme
  // Formats can be:
  // - "PKIX_ECDSA_P256_SHA_256" (production format)
  // - "PKIX_ED25519"
  // - "ecdsa-sha2-nistp256" (SSH/test format)
  const keyDetails = tlog.publicKey.keyDetails;
  let keyType: string;
  let scheme: string;

  if (keyDetails === "ecdsa-sha2-nistp256") {
    // SSH-style ECDSA P-256 format used in tests
    keyType = "ecdsa";
    scheme = "P256-SHA256";
  } else if (keyDetails.includes("ECDSA")) {
    keyType = "ecdsa";
    // Extract the curve and hash, e.g., "P256_SHA_256" from "PKIX_ECDSA_P256_SHA_256"
    scheme = keyDetails.replace("PKIX_ECDSA_", "").replaceAll("_", "-");
  } else if (keyDetails.includes("ED25519")) {
    keyType = "ed25519";
    scheme = "ed25519";
  } else if (keyDetails.includes("RSA")) {
    keyType = "rsa";
    // Extract RSA details, e.g., "PSS_SHA_256" from "PKIX_RSA_PSS_SHA_256"
    scheme = keyDetails.replace("PKIX_RSA_", "").replaceAll("_", "-");
  } else {
    throw new Error(`Unsupported key type in keyDetails: ${keyDetails}`);
  }

  return importKey(
    keyType,
    scheme,
    tlog.publicKey.rawBytes
  );
}
