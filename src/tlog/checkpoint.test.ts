import { describe, it, expect } from "vitest";
import { SignedNote, LogCheckpoint, verifyCheckpoint } from "./checkpoint.js";
import { base64ToUint8Array, Uint8ArrayToBase64 } from "../encoding.js";
import type { TLogEntry } from "../bundle.js";
import type { RawLogs } from "../interfaces.js";

describe("Checkpoint parsing", () => {
  it("should parse valid checkpoint", () => {
    const checkpointText = `rekor.sigstore.dev - 2605736670972794746
12345
SGVsbG8gV29ybGQh
`;

    const checkpoint = LogCheckpoint.fromString(checkpointText);

    expect(checkpoint.origin).toBe(
      "rekor.sigstore.dev - 2605736670972794746"
    );
    expect(checkpoint.logSize).toBe(12345n);
    expect(checkpoint.rest).toEqual([]);
  });

  it("should reject checkpoint with too few lines", () => {
    const checkpointText = `rekor.sigstore.dev
12345`;

    expect(() => LogCheckpoint.fromString(checkpointText)).toThrow(
      "Too few lines"
    );
  });

  it("should parse signed note with signatures", () => {
    const envelope = `rekor.sigstore.dev - 2605736670972794746
12345
SGVsbG8gV29ybGQh

— rekor.sigstore.dev dGVzdHRlc3R0ZXN0dGVzdHRlc3Q=
`;

    const signedNote = SignedNote.fromString(envelope);

    expect(signedNote.note).toContain("rekor.sigstore.dev");
    expect(signedNote.signatures).toHaveLength(1);
    expect(signedNote.signatures[0].name).toBe("rekor.sigstore.dev");
  });

  it("should reject envelope without separator", () => {
    const envelope = "rekor.sigstore.dev\n12345\nSGVsbG8gV29ybGQh";

    expect(() => SignedNote.fromString(envelope)).toThrow(
      "Missing checkpoint separator"
    );
  });

  it("should reject envelope without signatures", () => {
    const envelope = "rekor.sigstore.dev\n12345\nSGVsbG8gV29ybGQh\n\n";

    expect(() => SignedNote.fromString(envelope)).toThrow(
      "No signatures found"
    );
  });

  it("should reject malformed signatures", () => {
    const envelope = `rekor.sigstore.dev
12345
SGVsbG8gV29ybGQh

— rekor.sigstore.dev dGU=
`;

    expect(() => SignedNote.fromString(envelope)).toThrow(
      "Malformed checkpoint signature"
    );
  });
});

describe("Checkpoint verification", () => {
  describe("with real production Rekor data", () => {
    it("should verify valid checkpoint from production", async () => {
      const keyBytes = base64ToUint8Array(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="
      );

      const keyId = new Uint8Array(
        await crypto.subtle.digest("SHA-256", keyBytes)
      );

      const tlogs: RawLogs = [
        {
          baseUrl: "https://rekor.sigstore.dev",
          hashAlgorithm: "sha256",
          publicKey: {
            rawBytes: Uint8ArrayToBase64(keyBytes),
            keyDetails: "ecdsa-sha2-nistp256",
            validFor: {
              start: "2000-01-01T00:00:00Z",
              end: "2100-01-01T00:00:00Z",
            },
          },
          logId: {
            keyId: Uint8ArrayToBase64(keyId),
          },
        },
      ];

      const checkpoint =
        "rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\nTimestamp: 1688058656037355364\n\n— rekor.sigstore.dev wNI9ajBFAiEAuDk7uu5Ae8Own/MjhSZNuVzbLuYH2jBMxbSA0WaNDNACIDV4reKpYiOpkwtvazCClnpUuduF2o/th2xR3gRZAUU4\n";

      const entry: TLogEntry = {
        logIndex: "21428036",
        logId: {
          keyId: Uint8ArrayToBase64(keyId),
        },
        kindVersion: {
          kind: "hashedrekord",
          version: "0.0.1",
        },
        integratedTime: "1688058655",
        canonicalizedBody: "test",
        inclusionProof: {
          logIndex: "21428036",
          rootHash: "rxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=",
          treeSize: "21428036",
          hashes: [],
          checkpoint: {
            envelope: checkpoint,
          },
        },
      };

      await expect(verifyCheckpoint(entry, tlogs)).resolves.not.toThrow();
    });

    it("should verify checkpoint without timestamp field", async () => {
      const stagingKeyBytes = base64ToUint8Array(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEDODRU688UYGuy54mNUlaEBiQdTE9nYLr0lg6RXowI/QV/RE1azBn4Eg5/2uTOMbhB1/gfcHzijzFi9Tk+g1Prg=="
      );

      const stagingKeyId = new Uint8Array(
        await crypto.subtle.digest("SHA-256", stagingKeyBytes)
      );

      const tlogs: RawLogs = [
        {
          baseUrl: "https://rekor.sigstage.dev",
          hashAlgorithm: "sha256",
          publicKey: {
            rawBytes: Uint8ArrayToBase64(stagingKeyBytes),
            keyDetails: "ecdsa-sha2-nistp256",
            validFor: {
              start: "2000-01-01T00:00:00Z",
              end: "2100-01-01T00:00:00Z",
            },
          },
          logId: {
            keyId: Uint8ArrayToBase64(stagingKeyId),
          },
        },
      ];

      const checkpointNoTimestamp =
        "rekor.sigstage.dev - 8050909264565447525\n23003647\nWBwYpazawqUG5iErvDptvf7mpt84WIpmm+zfshgHhJs=\n\n— rekor.sigstage.dev 0y8wozBGAiEA2kq45YWfHHiDCJHH2+m9l+TVMtPBpOVu+VtVaj62V2MCIQDflbM2N7M/JTIV/spr9qYUI3gf4bO0qqSeiEWJ5xLgPA==\n";

      const entry: TLogEntry = {
        logIndex: "23003647",
        logId: {
          keyId: Uint8ArrayToBase64(stagingKeyId),
        },
        kindVersion: {
          kind: "hashedrekord",
          version: "0.0.1",
        },
        integratedTime: "1707034118",
        canonicalizedBody: "test",
        inclusionProof: {
          logIndex: "23003647",
          rootHash: "WBwYpazawqUG5iErvDptvf7mpt84WIpmm+zfshgHhJs=",
          treeSize: "23003647",
          hashes: [],
          checkpoint: {
            envelope: checkpointNoTimestamp,
          },
        },
      };

      await expect(verifyCheckpoint(entry, tlogs)).resolves.not.toThrow();
    });
  });

  describe("error cases", () => {
    it("should reject checkpoint with wrong root hash", async () => {
      const keyBytes = base64ToUint8Array(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="
      );

      const keyId = new Uint8Array(
        await crypto.subtle.digest("SHA-256", keyBytes)
      );

      const tlogs: RawLogs = [
        {
          baseUrl: "https://rekor.sigstore.dev",
          hashAlgorithm: "sha256",
          publicKey: {
            rawBytes: Uint8ArrayToBase64(keyBytes),
            keyDetails: "ecdsa-sha2-nistp256",
            validFor: {
              start: "2000-01-01T00:00:00Z",
              end: "2100-01-01T00:00:00Z",
            },
          },
          logId: {
            keyId: Uint8ArrayToBase64(keyId),
          },
        },
      ];

      const checkpoint =
        "rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\nTimestamp: 1688058656037355364\n\n— rekor.sigstore.dev wNI9ajBFAiEAuDk7uu5Ae8Own/MjhSZNuVzbLuYH2jBMxbSA0WaNDNACIDV4reKpYiOpkwtvazCClnpUuduF2o/th2xR3gRZAUU4\n";

      const entry: TLogEntry = {
        logIndex: "21428036",
        logId: {
          keyId: Uint8ArrayToBase64(keyId),
        },
        kindVersion: {
          kind: "hashedrekord",
          version: "0.0.1",
        },
        integratedTime: "1688058655",
        canonicalizedBody: "test",
        inclusionProof: {
          logIndex: "21428036",
          rootHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          treeSize: "21428036",
          hashes: [],
          checkpoint: {
            envelope: checkpoint,
          },
        },
      };

      await expect(verifyCheckpoint(entry, tlogs)).rejects.toThrow(
        "Root hash mismatch"
      );
    });

    it("should reject checkpoint with bad signature", async () => {
      const keyBytes = base64ToUint8Array(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="
      );

      const keyId = new Uint8Array(
        await crypto.subtle.digest("SHA-256", keyBytes)
      );

      const tlogs: RawLogs = [
        {
          baseUrl: "https://rekor.sigstore.dev",
          hashAlgorithm: "sha256",
          publicKey: {
            rawBytes: Uint8ArrayToBase64(keyBytes),
            keyDetails: "ecdsa-sha2-nistp256",
            validFor: {
              start: "2000-01-01T00:00:00Z",
              end: "2100-01-01T00:00:00Z",
            },
          },
          logId: {
            keyId: Uint8ArrayToBase64(keyId),
          },
        },
      ];

      const badCheckpoint =
        "rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\n\n— rekor.sigstore.dev xNI9ajBFAiEAuDk7uu5Ae8Own/MjhSZNuVzbLuYH2jBMxbSA0WaNDNACIDV4reKpYiOpkwtvazCClnpUuduF2o/th2xR3gRZAUU4\n";

      const entry: TLogEntry = {
        logIndex: "21428036",
        logId: {
          keyId: Uint8ArrayToBase64(keyId),
        },
        kindVersion: {
          kind: "hashedrekord",
          version: "0.0.1",
        },
        integratedTime: "1688058655",
        canonicalizedBody: "test",
        inclusionProof: {
          logIndex: "21428036",
          rootHash: "rxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=",
          treeSize: "21428036",
          hashes: [],
          checkpoint: {
            envelope: badCheckpoint,
          },
        },
      };

      await expect(verifyCheckpoint(entry, tlogs)).rejects.toThrow(
        "Invalid checkpoint signature"
      );
    });

    it("should reject checkpoint when key is expired", async () => {
      const keyBytes = base64ToUint8Array(
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw=="
      );

      const keyId = new Uint8Array(
        await crypto.subtle.digest("SHA-256", keyBytes)
      );

      const tlogs: RawLogs = [
        {
          baseUrl: "https://rekor.sigstore.dev",
          hashAlgorithm: "sha256",
          publicKey: {
            rawBytes: Uint8ArrayToBase64(keyBytes),
            keyDetails: "ecdsa-sha2-nistp256",
            validFor: {
              start: "2000-01-01T00:00:00Z",
              end: "2001-01-01T00:00:00Z",
            },
          },
          logId: {
            keyId: Uint8ArrayToBase64(keyId),
          },
        },
      ];

      const checkpoint =
        "rekor.sigstore.dev - 2605736670972794746\n21428036\nrxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=\n\n— rekor.sigstore.dev wNI9ajBFAiEAuDk7uu5Ae8Own/MjhSZNuVzbLuYH2jBMxbSA0WaNDNACIDV4reKpYiOpkwtvazCClnpUuduF2o/th2xR3gRZAUU4\n";

      const entry: TLogEntry = {
        logIndex: "21428036",
        logId: {
          keyId: Uint8ArrayToBase64(keyId),
        },
        kindVersion: {
          kind: "hashedrekord",
          version: "0.0.1",
        },
        integratedTime: "1688058655",
        canonicalizedBody: "test",
        inclusionProof: {
          logIndex: "21428036",
          rootHash: "rxnoKyFZlJ7/R6bMh/d3lcqwKqAy5CL1LcNBJP17kgQ=",
          treeSize: "21428036",
          hashes: [],
          checkpoint: {
            envelope: checkpoint,
          },
        },
      };

      await expect(verifyCheckpoint(entry, tlogs)).rejects.toThrow(
        "Invalid checkpoint signature"
      );
    });
  });
});
