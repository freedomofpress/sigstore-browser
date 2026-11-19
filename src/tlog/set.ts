import { base64ToUint8Array, canonicalizeJCS, stringToUint8Array, Uint8ArrayToHex, verifySignature } from "@freedomofpress/crypto-browser";

import type { TLogEntry } from "../bundle.js";
import type { RekorKeyInfo } from "../interfaces.js";

// Verifies an entry's signed entry timestamp (inclusion promise) and returns the integrated time it binds.
export async function verifyInclusionPromise(entry: TLogEntry, promise: string, log: RekorKeyInfo): Promise<Date> {
  const integratedTime = Number(entry.integratedTime);
  const integratedDate = new Date(integratedTime * 1000);
  const validAtIntegration = !(integratedDate < log.validFor.start || integratedDate > log.validFor.end);
  if (!validAtIntegration) {
    throw new Error("Rekor key was not valid at the integrated time.");
  }
  const canonicalEntry = canonicalizeJCS({
    body: entry.canonicalizedBody,
    integratedTime,
    logIndex: Number(entry.logIndex),
    logID: Uint8ArrayToHex(log.logId),
  });
  const signed = stringToUint8Array(canonicalEntry);
  const signature = base64ToUint8Array(promise);
  const verified = await verifySignature(log.publicKey, signed, signature, log.hashAlgorithm);
  if (!verified) {
    throw new Error("Failed to verify the inclusion promise in the provided bundle.");
  }
  return integratedDate;
}
