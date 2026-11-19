import { describe, expect, inject, it } from "vitest";

import { checkManagedKeyCorpus, expectedFor, type How, type Lib, type Mode } from "../test/corpus/check.ts";
import * as lib from "./index.js";

// The shared corpus stays unchanged. Browser exceptions, including JSON.parse handling of repeated
// member names, are recorded in test/corpus/check.ts.
const corpus = inject("corpus");

// Stand-ins for ManagedKeyVerifier, to show that the checks fail for a verifier that is wrong.
class AcceptAll {
  async loadTrustedRoot() {}
  async verifyDsse() {}
}
class WrongReason extends AcceptAll {
  async verifyDsse() {
    throw new lib.VerificationError("bundle-malformed", "always");
  }
}
const withVerifier = (verifier: typeof AcceptAll) => ({ ...lib, ManagedKeyVerifier: verifier }) as unknown as Lib;

const CONFIGURATIONS: [Mode, How][] = [
  ["strict", "dsse"],
  ["strict", "artifact"],
  ["strict", "digest"],
  ["default", "dsse"],
  ["default", "artifact"],
  ["default", "digest"],
];

describe("managed-key corpus", () => {
  const rejected = corpus.managedKey.filter((v) => v.expected.profile.result === "reject").length;
  const accepted = corpus.managedKey.length - rejected;

  it("has all 56 vectors", () => {
    expect(corpus.managedKey).toHaveLength(56);
  });

  it("uses library reason codes for the browser expectations", () => {
    for (const vector of corpus.managedKey) {
      for (const mode of ["strict", "default"] as const) {
        const expected = expectedFor(vector, mode);
        if (expected.result === "reject") {
          expect(lib.REASON_CODES).toContain(expected.code);
        }
      }
    }
  });

  it("catches a verifier that accepts everything", async () => {
    const mismatches = await checkManagedKeyCorpus(withVerifier(AcceptAll), corpus.managedKey, "strict", "dsse");
    // Every profile-rejecting vector, plus every messageSignature vector, which verifyDsse must refuse.
    const refused = corpus.managedKey.filter(
      (v) => !JSON.parse(v.bundle).dsseEnvelope || v.expected.profile.result === "reject",
    );
    expect(mismatches).toHaveLength(refused.length);
  });

  it("catches a verifier that rejects for another reason", async () => {
    const mismatches = await checkManagedKeyCorpus(withVerifier(WrongReason), corpus.managedKey, "strict", "dsse");
    // Every vector, plus each negative whose parent is now rejected.
    expect(mismatches.length).toBeGreaterThanOrEqual(rejected + accepted);
  });


  it.each(CONFIGURATIONS)("%s configuration, %s", async (mode, how) => {
    expect(await checkManagedKeyCorpus(lib, corpus.managedKey, mode, how)).toEqual([]);
  });
});

