import { beforeAll, describe, expect, inject, it } from "vitest";

import type { Lib } from "../test/corpus/check.ts";
import { removeNativeEd25519 } from "../test/no-ed25519.ts";

// Ed25519 (the Rekor v2 checkpoint signature) through upstream's @noble/curves fallback: WebCrypto
// rejects Ed25519 before crypto-browser first reads crypto.subtle. The full corpus must then give
// the same results.
removeNativeEd25519();

const corpus = inject("corpus");

// An Ed25519 Rekor v2 log key from the production trusted root.
const REKOR_V2_LOG_KEY = "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=";

describe("managed-key verification with the Ed25519 fallback", () => {
  let lib: Lib;

  beforeAll(async () => {
    const noble = await import("@freedomofpress/crypto-browser/noble");
    await noble.installEd25519Fallback();
    lib = await import("./index.js");
  });

  it("runs without native Ed25519", async () => {
    await expect(crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])).rejects.toThrow();
  });

  it("loads the Rekor v2 log key as a fallback key, not a native CryptoKey", async () => {
    const verifier = new lib.ManagedKeyVerifier();
    await verifier.loadTrustedRoot(JSON.parse(corpus.managedKey[0].root));
    const { importKey } = await import("@freedomofpress/crypto-browser");
    const key = await importKey("PKIX_ED25519", "PKIX_ED25519", REKOR_V2_LOG_KEY);
    expect((key as unknown as { __fallback__?: boolean }).__fallback__).toBe(true);
  });

  it.each(["strict", "default"] as const)("verifies the corpus in the %s configuration", async (mode) => {
    const { checkManagedKeyCorpus } = await import("../test/corpus/check.ts");
    expect(await checkManagedKeyCorpus(lib, corpus.managedKey, mode, "dsse")).toEqual([]);
  });
});
