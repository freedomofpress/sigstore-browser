import { base64ToUint8Array, stringToUint8Array } from "../encoding.js";

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
