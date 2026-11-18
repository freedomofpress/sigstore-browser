import { describe, expect, inject, it } from "vitest";

import type { ManagedKeyVector } from "../test/corpus/data.ts";
import { base64ToBytes, reason, vector } from "../test/helpers.ts";
import { ManagedPublicKey } from "./key.js";
import { verifyTLogBody } from "./tlog/body.js";

// Log entry bodies from the vendored corpus, checked directly against a caller's key: the binding
// of the logged key, key details, digest algorithm and length, signature and digest.
const corpus = inject("corpus");

const p384 = vector(corpus.managedKey, "p384-rekor2-dsse-tsa");
const otherP384 = vector(corpus.managedKey, "p384-rekor2-dsse-tsa-second-key");
const p256 = vector(corpus.managedKey, "p256-rekor2-dsse-tsa");

const BODY_CODES = new Set([
  "tlog-key-mismatch",
  "tlog-key-details-mismatch",
  "tlog-digest-algorithm-mismatch",
  "tlog-digest-malformed",
  "tlog-digest-mismatch",
  "tlog-signature-mismatch",
]);

function pemToDer(pem: string): Uint8Array {
  const encodedKey = pem.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, "");
  return base64ToBytes(encodedKey);
}

function verifyBody(v: ManagedKeyVector, key = v.key) {
  const bundle = JSON.parse(v.bundle);
  const entry = bundle.verificationMaterial.tlogEntries[0];
  const signer = ManagedPublicKey.from(key);
  return reason(() => verifyTLogBody(entry, bundle, signer));
}

describe("ManagedPublicKey", () => {
  it("reads a P-384 PEM public key", () => {
    const key = ManagedPublicKey.from(p384.key);
    expect(key.namedCurve).toBe("P-384");
    expect(key.keyDetails).toBe("PKIX_ECDSA_P384_SHA_384");
    expect(key.digestAlgorithm).toBe("SHA2_384");
  });

  it("reads the same key from DER SubjectPublicKeyInfo", () => {
    const der = pemToDer(p384.key);
    const keyFromDer = ManagedPublicKey.from(der);
    const keyFromPem = ManagedPublicKey.from(p384.key);
    expect(keyFromDer.spki).toEqual(keyFromPem.spki);
  });

  it("reads a P-256 key", () => {
    const key = ManagedPublicKey.from(p256.key);
    expect(key.namedCurve).toBe("P-256");
    expect(key.digestAlgorithm).toBe("SHA2_256");
  });

  it.each([
    { name: "an empty string", key: "" },
    { name: "a certificate", key: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----" },
    { name: "empty bytes", key: new Uint8Array(0) },
    { name: "an Ed25519 key", key: base64ToBytes("MCowBQYDK2VwAyEAfg2lwbzIodFZAVb9h+ZQIuzZWRCgofcsdgoOB5BRBmk=") },
  ])("rejects $name as key-unsupported", async ({ key }) => {
    expect(await reason(() => ManagedPublicKey.from(key))).toBe("key-unsupported");
  });
});

describe("transparency log body checks with a managed key", () => {
  it.each(["p384-rekor2-dsse-tsa", "p256-rekor2-dsse-tsa", "p384-rekor1-dsse-synthetic"])(
    "binds the %s entry to its bundle and key",
    async (id) => {
      const fixture = vector(corpus.managedKey, id);
      const actualReason = await verifyBody(fixture);
      expect(actualReason).toBe("accept");
    },
  );

  it("rejects an entry logged under another key as tlog-key-mismatch", async () => {
    expect(await verifyBody(p384, otherP384.key)).toBe("tlog-key-mismatch");
  });

  // Every corpus vector whose first failing check is a body check fails it here too.
  const bodyVectors = corpus.managedKey.filter((candidate) => {
    const profile = candidate.expected.profile;
    if (profile.result !== "reject") {
      return false;
    }
    return BODY_CODES.has(profile.code);
  });
  const bodyNegatives = bodyVectors.map((v) => {
    const profile = v.expected.profile;
    if (profile.result !== "reject") {
      throw new Error("expected a rejecting body vector");
    }
    return { id: v.id, code: profile.code, v };
  });

  it("has corpus vectors for every body check", () => {
    const codes = bodyNegatives.map((negative) => negative.code);
    expect(new Set(codes)).toEqual(BODY_CODES);
  });

  it.each(bodyNegatives)("rejects $id as $code", async ({ code, v }) => {
    expect(await verifyBody(v)).toBe(code);
  });
});
