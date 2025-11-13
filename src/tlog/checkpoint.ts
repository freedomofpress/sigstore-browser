import { base64ToUint8Array, stringToUint8Array } from "../encoding.js";
import { verifySignature } from "../crypto.js";
import type { TLogEntry } from "../bundle.js";
import type { RawLogs } from "../interfaces.js";

const CHECKPOINT_SEPARATOR = "\n\n";
const SIGNATURE_REGEX = /\u2014 (\S+) (\S+)\n/g;

export interface TLogSignature {
  name: string;
  keyHint: Uint8Array;
  signature: Uint8Array;
}

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

    const split = envelope.indexOf(CHECKPOINT_SEPARATOR);
    const header = envelope.slice(0, split + 1);
    const data = envelope.slice(split + CHECKPOINT_SEPARATOR.length);

    const matches = data.matchAll(SIGNATURE_REGEX);

    const signatures: TLogSignature[] = [];
    for (const match of matches) {
      const [, name, signature] = match;
      const sigBytes = base64ToUint8Array(signature);

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

export async function verifyCheckpoint(
  entry: TLogEntry,
  tlogs: RawLogs
): Promise<void> {
  if (!entry.inclusionProof?.checkpoint) {
    throw new Error("Missing checkpoint in inclusion proof");
  }

  const integratedTime = new Date(Number(entry.integratedTime) * 1000);
  const validTLogs = filterTLogsByDate(tlogs, integratedTime);

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

async function verifySignedNote(
  signedNote: SignedNote,
  tlogs: RawLogs
): Promise<boolean> {
  const data = stringToUint8Array(signedNote.note);

  for (const signature of signedNote.signatures) {
    const tlog = tlogs.find((tlog) => {
      const logId = base64ToUint8Array(tlog.logId.keyId);
      return uint8ArrayEqual(logId.subarray(0, 4), signature.keyHint);
    });

    if (!tlog) {
      return false;
    }

    const publicKey = await importTLogKey(tlog);

    // ED25519 signatures are raw (64 bytes), ECDSA signatures are DER-encoded
    const isEd25519 = tlog.publicKey.keyDetails.includes("ED25519");
    let verified: boolean;

    if (isEd25519) {
      // ED25519 uses raw signatures
      verified = await verifyRawSignature(publicKey, data, signature.signature);
    } else {
      // ECDSA uses DER-encoded signatures
      verified = await verifySignature(
        publicKey,
        data,
        signature.signature,
        tlog.hashAlgorithm
      );
    }

    if (!verified) {
      return false;
    }
  }

  return true;
}

async function verifyRawSignature(
  key: CryptoKey,
  signed: Uint8Array,
  rawSig: Uint8Array,
): Promise<boolean> {
  const { toArrayBuffer } = await import("../encoding.js");

  return await crypto.subtle.verify(
    key.algorithm.name,
    key,
    toArrayBuffer(rawSig),
    toArrayBuffer(signed),
  );
}

function filterTLogsByDate(tlogs: RawLogs, targetDate: Date): RawLogs {
  return tlogs.filter((tlog) => {
    const start = new Date(tlog.publicKey.validFor.start);
    const end = tlog.publicKey.validFor.end
      ? new Date(tlog.publicKey.validFor.end)
      : null;

    return targetDate >= start && (!end || targetDate <= end);
  });
}

async function importTLogKey(tlog: RawLogs[0]): Promise<CryptoKey> {
  const { importKey } = await import("../crypto.js");

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

function uint8ArrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}
