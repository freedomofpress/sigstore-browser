import { base64ToUint8Array, hashLeaf, verifyInclusionProof } from "@freedomofpress/crypto-browser";

import type { TLogEntry } from "../bundle.js";

export async function verifyMerkleInclusion(entry: TLogEntry): Promise<void> {
  if (!entry.inclusionProof) {
    throw new Error("Missing inclusion proof");
  }
  const proof = entry.inclusionProof;
  const index = Number(proof.logIndex);
  const size = Number(proof.treeSize);
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(size) || index < 0 || index >= size) {
    throw new Error(`Invalid log index: ${proof.logIndex}`);
  }
  const leafHash = await hashLeaf(base64ToUint8Array(entry.canonicalizedBody));
  const ok = await verifyInclusionProof(
    leafHash,
    index,
    size,
    base64ToUint8Array(proof.rootHash),
    proof.hashes.map(base64ToUint8Array),
  );
  if (!ok) {
    throw new Error("Calculated root hash does not match inclusion proof");
  }
}
