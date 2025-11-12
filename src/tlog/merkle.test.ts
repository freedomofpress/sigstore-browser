import { describe, it, expect } from "vitest";
import { verifyMerkleInclusion } from "./merkle.js";
import {
  Uint8ArrayToBase64,
  stringToUint8Array,
} from "../encoding.js";
import type { TLogEntry } from "../bundle.js";

describe("Merkle tree verification", () => {
  describe("with simple test cases", () => {
    it("should verify smallest possible tree (size 1)", async () => {
      const body = stringToUint8Array("foo");
      const leafWithPrefix = new Uint8Array(1 + body.length);
      leafWithPrefix.set([0x00], 0);
      leafWithPrefix.set(body, 1);

      const rootHash = await crypto.subtle.digest("SHA-256", leafWithPrefix);
      const rootHashBase64 = Uint8ArrayToBase64(new Uint8Array(rootHash));

      const entry: TLogEntry = {
        logIndex: "0",
        logId: {
          keyId: "dGVzdA==",
        },
        kindVersion: {
          kind: "hashedrekord",
          version: "0.0.1",
        },
        integratedTime: "1234567890",
        canonicalizedBody: Uint8ArrayToBase64(body),
        inclusionProof: {
          logIndex: "0",
          rootHash: rootHashBase64,
          treeSize: "1",
          hashes: [],
          checkpoint: {
            envelope: "",
          },
        },
      };

      await expect(verifyMerkleInclusion(entry)).resolves.not.toThrow();
    });

    it("should reject entry with mismatched body", async () => {
      const goodBody = stringToUint8Array("foo");
      const badBody = stringToUint8Array("bar");

      const leafWithPrefix = new Uint8Array(1 + goodBody.length);
      leafWithPrefix.set([0x00], 0);
      leafWithPrefix.set(goodBody, 1);

      const rootHash = await crypto.subtle.digest("SHA-256", leafWithPrefix);
      const rootHashBase64 = Uint8ArrayToBase64(new Uint8Array(rootHash));

      const entry: TLogEntry = {
        logIndex: "0",
        logId: {
          keyId: "dGVzdA==",
        },
        kindVersion: {
          kind: "hashedrekord",
          version: "0.0.1",
        },
        integratedTime: "1234567890",
        canonicalizedBody: Uint8ArrayToBase64(badBody),
        inclusionProof: {
          logIndex: "0",
          rootHash: rootHashBase64,
          treeSize: "1",
          hashes: [],
          checkpoint: {
            envelope: "",
          },
        },
      };

      await expect(verifyMerkleInclusion(entry)).rejects.toThrow(
        "Calculated root hash does not match"
      );
    });
  });

  it("should reject invalid log index", async () => {
    const entry: TLogEntry = {
      logIndex: "10",
      logId: {
        keyId: "dGVzdA==",
      },
      kindVersion: {
        kind: "hashedrekord",
        version: "0.0.1",
      },
      integratedTime: "1234567890",
      canonicalizedBody: "dGVzdCBkYXRh",
      inclusionProof: {
        logIndex: "10",
        rootHash: "test",
        treeSize: "5",
        hashes: [],
        checkpoint: {
          envelope: "",
        },
      },
    };

    await expect(verifyMerkleInclusion(entry)).rejects.toThrow(
      "Invalid log index"
    );
  });

  it("should reject missing inclusion proof", async () => {
    const entry: TLogEntry = {
      logIndex: "0",
      logId: {
        keyId: "dGVzdA==",
      },
      kindVersion: {
        kind: "hashedrekord",
        version: "0.0.1",
      },
      integratedTime: "1234567890",
      canonicalizedBody: "dGVzdCBkYXRh",
    };

    await expect(verifyMerkleInclusion(entry)).rejects.toThrow(
      "Missing inclusion proof"
    );
  });

  it("should reject invalid hash count", async () => {
    const entry: TLogEntry = {
      logIndex: "2",
      logId: {
        keyId: "dGVzdA==",
      },
      kindVersion: {
        kind: "hashedrekord",
        version: "0.0.1",
      },
      integratedTime: "1234567890",
      canonicalizedBody: "dGVzdCBkYXRh",
      inclusionProof: {
        logIndex: "2",
        rootHash: "test",
        treeSize: "8",
        hashes: ["dGVzdA=="],
        checkpoint: {
          envelope: "",
        },
      },
    };

    await expect(verifyMerkleInclusion(entry)).rejects.toThrow(
      "Invalid hash count"
    );
  });
});
