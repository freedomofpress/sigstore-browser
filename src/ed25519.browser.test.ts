import { describe, expect, it } from "vitest";

// Replace crypto.subtle with a wrapper whose Ed25519 operations throw NotSupportedError, as browsers without native
// Ed25519 do. It must be in place before crypto-browser is first imported, because it probes once and caches the result.
const real = globalThis.crypto.subtle;
const noEd25519 = new Proxy(real, {
  get(target, prop) {
    const value = Reflect.get(target, prop) as unknown;
    if (typeof value !== "function") return value;
    return (...args: unknown[]) => {
      const alg = (prop === "importKey" ? args[2] : args[0]) as { name?: string } | undefined;
      if (alg?.name === "Ed25519") {
        return Promise.reject(new DOMException("Unrecognized name.", "NotSupportedError"));
      }
      return (value as (...a: unknown[]) => unknown).apply(target, args);
    };
  },
});
Object.defineProperty(globalThis.crypto, "subtle", { value: noEd25519, configurable: true });

describe("Fix 7: Ed25519 log keys without native WebCrypto support", () => {
  it("imports trusted root Ed25519 keys through the fallback and verifies a checkpoint", async () => {
    await expect(crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])).rejects.toThrow();

    const { SigstoreVerifier } = await import("./sigstore.js");
    const { verifyCheckpoint } = await import("./tlog/checkpoint.js");
    const { Uint8ArrayToBase64 } = await import("@freedomofpress/crypto-browser");
    const { ed25519 } = await import("@noble/curves/ed25519.js");
    const { trustRoot } = await import("../test/fixtures/sigstore.js");

    // The real trusted root carries an SPKI-encoded Ed25519 key for Rekor v2.
    const keys = await new SigstoreVerifier().loadLog(trustRoot().tlogs);
    const rekorV2 = keys.find((k) => k.publicKey.algorithm.name === "Ed25519");
    expect((rekorV2?.publicKey as unknown as { bytes: Uint8Array }).bytes).toHaveLength(32);

    // A synthetic log whose key we control, signing a checkpoint note.
    const priv = ed25519.utils.randomSecretKey();
    const pub = ed25519.getPublicKey(priv);
    const spki = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...pub]);
    const logId = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
    const [log] = await new SigstoreVerifier().loadLog([
      {
        baseUrl: "https://log.test",
        hashAlgorithm: "SHA2_256",
        publicKey: { rawBytes: Uint8ArrayToBase64(spki), keyDetails: "PKIX_ED25519", validFor: { start: "2025-01-01T00:00:00Z" } },
        logId: { keyId: Uint8ArrayToBase64(logId) },
      },
    ]);

    const rootHash = Uint8ArrayToBase64(new Uint8Array(32));
    const note = `log.test\n7\n${rootHash}\n`;
    const sig = ed25519.sign(new TextEncoder().encode(note), priv);
    const sigLine = Uint8ArrayToBase64(new Uint8Array([...logId.subarray(0, 4), ...sig]));
    const proof = (n: string) => ({
      logIndex: "0",
      hashes: [],
      treeSize: "7",
      rootHash,
      checkpoint: { envelope: `${n}\n— log.test ${sigLine}\n` },
    });
    const entry = (n = note) => ({
      logIndex: "0",
      logId: { keyId: Uint8ArrayToBase64(logId) },
      kindVersion: { kind: "dsse", version: "0.0.2" },
      integratedTime: null,
      canonicalizedBody: "",
      inclusionProof: proof(n),
    });

    await expect(verifyCheckpoint(entry(), log)).resolves.toBeUndefined();
    await expect(verifyCheckpoint(entry(`log.test\n8\n${rootHash}\n`), log)).rejects.toThrow("Invalid checkpoint signature");
    const bad = entry();
    bad.inclusionProof.treeSize = "8";
    await expect(verifyCheckpoint(bad, log)).rejects.toThrow("does not match inclusion proof");
  });
});
