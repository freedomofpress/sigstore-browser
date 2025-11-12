/*
Adapted from sigstore-js for browser compatibility:
https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/timestamp/merkle.ts

Key differences:
- Uses Uint8Array instead of Buffer
- Uses async Web Crypto API (crypto.subtle.digest) instead of sync Node.js crypto
- Base64 decoding via custom base64ToUint8Array instead of Buffer.from
- Custom uint8ArrayEqual instead of crypto.bufferEqual
*/
import { base64ToUint8Array, toArrayBuffer, uint8ArrayEqual } from "../encoding.js";
import type { TLogEntry } from "../bundle.js";

const RFC6962_LEAF_HASH_PREFIX = new Uint8Array([0x00]);
const RFC6962_NODE_HASH_PREFIX = new Uint8Array([0x01]);

export async function verifyMerkleInclusion(
  entry: TLogEntry
): Promise<void> {
  if (!entry.inclusionProof) {
    throw new Error("Missing inclusion proof");
  }

  const inclusionProof = entry.inclusionProof;
  const logIndex = BigInt(inclusionProof.logIndex);
  const treeSize = BigInt(inclusionProof.treeSize);

  if (logIndex < 0n || logIndex >= treeSize) {
    throw new Error(`Invalid log index: ${logIndex}`);
  }

  // Figure out which subset of hashes corresponds to the inner and border
  // nodes
  const { inner, border } = decompInclProof(logIndex, treeSize);

  if (inclusionProof.hashes.length !== inner + border) {
    throw new Error("Invalid hash count in inclusion proof");
  }

  const innerHashes = inclusionProof.hashes
    .slice(0, inner)
    .map((h) => base64ToUint8Array(h));
  const borderHashes = inclusionProof.hashes
    .slice(inner)
    .map((h) => base64ToUint8Array(h));

  // The entry's hash is the leaf hash
  const leafHash = await hashLeaf(base64ToUint8Array(entry.canonicalizedBody));

  // Chain the hashes belonging to the inner and border portions
  const calculatedHash = await chainBorderRight(
    await chainInner(leafHash, innerHashes, logIndex),
    borderHashes
  );

  const rootHash = base64ToUint8Array(inclusionProof.rootHash);

  // Calculated hash should match the root hash in the inclusion proof
  if (!uint8ArrayEqual(calculatedHash, rootHash)) {
    throw new Error("Calculated root hash does not match inclusion proof");
  }
}

// Breaks down inclusion proof for a leaf at the specified index in a tree of
// the specified size. The split point is where paths to the index leaf and
// the (size - 1) leaf diverge. Returns lengths of the bottom and upper proof
// parts.
function decompInclProof(
  index: bigint,
  size: bigint
): { inner: number; border: number } {
  const inner = innerProofSize(index, size);
  const border = onesCount(index >> BigInt(inner));
  return { inner, border };
}

// Computes a subtree hash for a node on or below the tree's right border.
// Assumes the provided proof hashes are ordered from lower to higher levels
// and seed is the initial hash of the node specified by the index.
async function chainInner(
  seed: Uint8Array,
  hashes: Uint8Array[],
  index: bigint
): Promise<Uint8Array> {
  let acc = seed;
  for (let i = 0; i < hashes.length; i++) {
    const h = hashes[i];
    if ((index >> BigInt(i)) & BigInt(1)) {
      acc = await hashChildren(h, acc);
    } else {
      acc = await hashChildren(acc, h);
    }
  }
  return acc;
}

// Computes a subtree hash for nodes along the tree's right border.
async function chainBorderRight(
  seed: Uint8Array,
  hashes: Uint8Array[]
): Promise<Uint8Array> {
  let acc = seed;
  for (const h of hashes) {
    acc = await hashChildren(h, acc);
  }
  return acc;
}

function innerProofSize(index: bigint, size: bigint): number {
  return bitLength(index ^ (size - BigInt(1)));
}

// Counts the number of ones in the binary representation of the given number.
// https://en.wikipedia.org/wiki/Hamming_weight
function onesCount(num: bigint): number {
  return num.toString(2).split("1").length - 1;
}

// Returns the number of bits necessary to represent an integer in binary.
function bitLength(n: bigint): number {
  if (n === 0n) {
    return 0;
  }
  return n.toString(2).length;
}

// Hashing logic according to RFC6962.
// https://datatracker.ietf.org/doc/html/rfc6962#section-2
async function hashChildren(
  left: Uint8Array,
  right: Uint8Array
): Promise<Uint8Array> {
  const data = new Uint8Array(
    RFC6962_NODE_HASH_PREFIX.length + left.length + right.length
  );
  data.set(RFC6962_NODE_HASH_PREFIX, 0);
  data.set(left, RFC6962_NODE_HASH_PREFIX.length);
  data.set(right, RFC6962_NODE_HASH_PREFIX.length + left.length);

  const hash = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
  return new Uint8Array(hash);
}

async function hashLeaf(leaf: Uint8Array): Promise<Uint8Array> {
  const data = new Uint8Array(RFC6962_LEAF_HASH_PREFIX.length + leaf.length);
  data.set(RFC6962_LEAF_HASH_PREFIX, 0);
  data.set(leaf, RFC6962_LEAF_HASH_PREFIX.length);

  const hash = await crypto.subtle.digest("SHA-256", toArrayBuffer(data));
  return new Uint8Array(hash);
}
