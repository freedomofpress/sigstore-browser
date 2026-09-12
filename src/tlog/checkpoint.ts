/*
Checkpoint verification for transparency log entries.

Adapted from sigstore-js for browser compatibility:
https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/timestamp/checkpoint.ts

Follows the signed note format specification:
https://github.com/transparency-dev/formats/blob/main/log/README.md
*/

import {
  base64ToUint8Array,
  stringToUint8Array,
  uint8ArrayEqual,
  verifySignature,
} from "@freedomofpress/crypto-browser";

import type { TLogEntry } from "../bundle.js";
import type { RekorKeyInfo } from "../interfaces.js";

// Signed note format per https://github.com/transparency-dev/formats
// Body is separated from signatures by a blank line
const CHECKPOINT_SEPARATOR = "\n\n";
// Signature lines format: "— <identity> <base64(key_hint+signature)>\n"
// — is the em-dash character (—)
const SIGNATURE_REGEX = /— (\S+) (\S+)\n/g;

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

// Verifies that the checkpoint is signed by the entry's log and describes the same tree as the inclusion proof.
export async function verifyCheckpoint(
  entry: TLogEntry,
  log: RekorKeyInfo
): Promise<void> {
  const proof = entry.inclusionProof;
  if (!proof?.checkpoint?.envelope) {
    throw new Error("Missing checkpoint in inclusion proof");
  }

  const signedNote = SignedNote.fromString(proof.checkpoint.envelope);
  const checkpoint = LogCheckpoint.fromString(signedNote.note);
  const data = stringToUint8Array(signedNote.note);

  // Signatures from other parties (e.g. witnesses) are ignored; the key hint is the first 4 bytes of the log ID.
  let valid = false;
  for (const sig of signedNote.signatures) {
    if (
      uint8ArrayEqual(sig.keyHint, log.logId.subarray(0, 4)) &&
      (await verifySignature(log.publicKey, data, sig.signature, log.hashAlgorithm))
    ) {
      valid = true;
    }
  }
  if (!valid) {
    throw new Error("Invalid checkpoint signature");
  }

  if (
    checkpoint.logSize !== BigInt(proof.treeSize) ||
    !uint8ArrayEqual(checkpoint.logHash, base64ToUint8Array(proof.rootHash))
  ) {
    throw new Error("Checkpoint does not match inclusion proof");
  }
}
