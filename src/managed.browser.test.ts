import { Uint8ArrayToBase64 } from "@freedomofpress/crypto-browser";
import { verifySignatureOverDigest } from "@freedomofpress/crypto-browser/noble";
import { describe, expect, inject, it } from "vitest";

import type { ManagedKeyVector } from "../test/corpus/data.ts";
import { bundle as keylessBundle } from "../test/fixtures/sigstore.js";
import { base64ToBytes, reason, vector } from "../test/helpers.ts";
import { ManagedKeyVerifier, type ManagedKeyVerifierOptions, STRICT_MANAGED_KEY_PROFILE } from "./managed.js";
import { SigstoreVerifier } from "./sigstore.js";

// Fixtures are real Cosign bundles from the vendored corpus. Tests parse them, change one thing and
// serialize them again, so parsed bundles and roots are plain mutable JSON.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

const corpus = inject("corpus");

const p384 = vector(corpus.managedKey, "p384-rekor2-dsse-tsa");
const otherP384 = vector(corpus.managedKey, "p384-rekor2-dsse-tsa-second-key");
const p256 = vector(corpus.managedKey, "p256-rekor2-dsse-tsa");
const v02 = vector(corpus.managedKey, "p384-media-type-v0.2");
// The day the corpus bundles were signed and timestamped.
const SIGNING_DAY = "2026-11-17";

const LEGACY_V01 = "application/vnd.dev.sigstore.bundle+json;version=0.1";
const LEGACY_V02 = "application/vnd.dev.sigstore.bundle+json;version=0.2";
const LEGACY_V03 = "application/vnd.dev.sigstore.bundle+json;version=0.3";
const CANONICAL_V01 = "application/vnd.dev.sigstore.bundle.v0.1+json";
const CANONICAL_V02 = "application/vnd.dev.sigstore.bundle.v0.2+json";
const CANONICAL_V03 = "application/vnd.dev.sigstore.bundle.v0.3+json";
const CANONICAL_V04 = "application/vnd.dev.sigstore.bundle.v0.4+json";

const STRICT = STRICT_MANAGED_KEY_PROFILE;
const DEFAULTS: ManagedKeyVerifierOptions = {};
const CANONICAL_ONLY: ManagedKeyVerifierOptions = { requireCanonicalMediaType: true };

const parse = (v: ManagedKeyVector): Json => JSON.parse(v.bundle);
const text = (bundle: unknown) => JSON.stringify(bundle, null, 2);

/** p384's bundle as text, after `change` has modified its parsed form. */
function changed(change: (bundle: Json) => void): string {
  const bundle = parse(p384);
  change(bundle);
  return text(bundle);
}

const withMediaType = (mediaType: unknown) =>
  changed((b) => {
    if (mediaType === undefined) delete b.mediaType;
    else b.mediaType = mediaType;
  });

async function verifier(options: ManagedKeyVerifierOptions = STRICT, root: Json = JSON.parse(p384.root)) {
  const v = new ManagedKeyVerifier(options);
  await v.loadTrustedRoot(root);
  return v;
}

/** Real Cosign blob bundles, including their Rekor entries and timestamps. */
async function messageSignatureFixture(curve: "P-256" | "P-384") {
  const id = curve === "P-384" ? "p384-rekor2-blob-tsa" : "p256-rekor2-blob-tsa";
  const source = vector(corpus.managedKey, id);
  const artifact = base64ToBytes(source.artifact);
  const hash = curve === "P-384" ? "SHA-384" : "SHA-256";
  const digest = new Uint8Array(await crypto.subtle.digest(hash, artifact));
  return { source, artifact, digest };
}

/**
 * p384's trusted root with logs, CT logs and timestamp authorities this library cannot load or does
 * not need: an unknown key type, a key that is not base64 DER, a malformed validity period, the
 * staging root's retired logs and RSA CT key, a CT key that does not parse, and broken authorities.
 */
function rootWithUnusableKeys(): Json {
  const root = JSON.parse(p384.root);
  const stagingRoot = JSON.parse(corpus.stagingRoot);
  const [log] = root.tlogs;
  const [ctLog] = root.ctlogs;
  const [authority] = root.timestampAuthorities;

  root.tlogs.push(
    {
      ...structuredClone(log),
      logId: { keyId: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=" },
      publicKey: { rawBytes: "AAAA", keyDetails: "PKIX_SOMETHING_NEW", validFor: { start: "2026-01-01T00:00:00Z" } },
    },
    {
      ...structuredClone(log),
      logId: { keyId: "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=" },
      publicKey: {
        rawBytes: "!!!",
        keyDetails: "PKIX_ECDSA_P256_SHA_256",
        validFor: { start: "2026-01-01T00:00:00Z" },
      },
    },
    {
      ...structuredClone(log),
      logId: { keyId: "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=" },
      publicKey: { ...structuredClone(log.publicKey), validFor: { start: "not a date" } },
    },
    ...stagingRoot.tlogs.filter((l: Json) => l.publicKey.validFor.end),
    "not an object",
  );
  root.ctlogs.push(
    ...stagingRoot.ctlogs.filter((l: Json) => l.publicKey.keyDetails === "PKCS1_RSA_PKCS1V5"),
    {
      ...structuredClone(ctLog),
      publicKey: {
        rawBytes: "AAAA",
        keyDetails: "PKIX_ECDSA_P256_SHA_256",
        validFor: { start: "2021-01-01T00:00:00Z" },
      },
    },
  );
  root.timestampAuthorities.push(
    { ...structuredClone(authority), validFor: { start: "not a date" } },
    { ...structuredClone(authority), certChain: { certificates: [{ rawBytes: "AAAA" }] } },
  );
  return root;
}

describe("ManagedKeyVerifier", () => {
  describe("verification", () => {
    it("verifies a P-384 DSSE bundle logged in Rekor v2 with a timestamp, using the caller's key", async () => {
      const v = await verifier();
      const result = await v.verifyDsse(p384.bundle, p384.key);

      expect(result.payloadType).toBe("application/vnd.in-toto+json");
      const statement = JSON.parse(new TextDecoder().decode(result.payload));
      expect(statement._type).toBe("https://in-toto.io/Statement/v1");
      expect(result.timestamps).toHaveLength(1);
      expect(result.timestamps[0].toISOString().slice(0, 10)).toBe(SIGNING_DAY);
    });

    it("accepts the bundle as UTF-8 bytes", async () => {
      const bytes = new TextEncoder().encode(p384.bundle);
      const v = await verifier();
      await expect(v.verifyDsse(bytes, p384.key)).resolves.toBeDefined();
    });

    it("accepts the key as DER SubjectPublicKeyInfo", async () => {
      const der = base64ToBytes(p384.key.replace(/-----[A-Z ]+-----/g, "").replace(/\s/g, ""));
      const v = await verifier();
      await expect(v.verifyDsse(p384.bundle, der)).resolves.toBeDefined();
    });

    it("verifies a P-256 bundle", async () => {
      const v = await verifier();
      await expect(v.verifyDsse(p256.bundle, p256.key)).resolves.toBeDefined();
    });

    it("accepts the artifact named by the statement subject", async () => {
      const artifact = base64ToBytes(p384.artifact);
      const v = await verifier();
      await expect(v.verifyArtifact(p384.bundle, p384.key, artifact)).resolves.toBe(true);
    });

    it("rejects an artifact that is not the statement subject", async () => {
      const other = new Uint8Array([1, 2, 3]);
      const v = await verifier();
      const actualReason = await reason(v.verifyArtifact(p384.bundle, p384.key, other));
      expect(actualReason).toBe("artifact-mismatch");
    });
  });

  describe("key authority", () => {
    it("rejects another key's bundle relabelled with this key's hint", async () => {
      const relabelled = parse(otherP384);
      relabelled.verificationMaterial.publicKey.hint = parse(p384).verificationMaterial.publicKey.hint;

      const v = await verifier();
      const actualReason = await reason(v.verifyDsse(text(relabelled), p384.key));
      expect(actualReason).toBe("dsse-signature-invalid");
    });

    it.each([
      { name: "removed", hint: undefined },
      { name: "empty", hint: "" },
      { name: "garbage", hint: "not-a-key" },
      { name: "another key's", hint: parse(otherP384).verificationMaterial.publicKey.hint },
    ])("ignores the key hint when it is $name", async ({ hint }) => {
      const bundle = changed((b) => {
        b.verificationMaterial.publicKey = hint === undefined ? {} : { hint };
      });
      const v = await verifier();

      const actualReason = await reason(v.verifyDsse(bundle, p384.key));
      expect(actualReason).toBe("accept");
      const otherKeyReason = await reason(v.verifyDsse(bundle, otherP384.key));
      expect(otherKeyReason).toBe("dsse-signature-invalid");
    });

    it.each([
      { name: "an empty string", key: "" },
      { name: "a certificate", key: "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----" },
      { name: "empty bytes", key: new Uint8Array(0) },
      { name: "an Ed25519 key", key: base64ToBytes("MCowBQYDK2VwAyEAfg2lwbzIodFZAVb9h+ZQIuzZWRCgofcsdgoOB5BRBmk=") },
      {
        name: "a P-521 key",
        key: base64ToBytes(
          "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBi44fj79FBp5ZzPNa72pTsvb5XCoFTD6ThQen+AAGN8NEIRXjN5xTE+krQerNc/oLlVAZ/O5rVrI3qdmMzXqgtuAB6JSxfEck6S0RtgG85EgesH5/1aXaFnM9j5H/2j4eccHrB2c6whfZkS39TLg3nJEfV01Z+O3XUl0gmrr5RUpZfAQ=",
        ),
      },
    ])("rejects $name as the caller's key", async ({ key }) => {
      const v = await verifier();
      const actualReason = await reason(v.verifyDsse(p384.bundle, key));
      expect(actualReason).toBe("key-unsupported");
    });
  });

  describe("certificate material", () => {
    const certificate = keylessBundle().verificationMaterial.certificate;

    it("has a certificate fixture", () => {
      expect(certificate?.rawBytes).toBeTruthy();
    });

    it.each([
      { profile: "strict", options: STRICT },
      { profile: "default", options: DEFAULTS },
    ])("rejects a certificate beside the public key ($profile)", async ({ options }) => {
      const bundle = changed((b) => {
        b.verificationMaterial.certificate = certificate;
      });
      const v = await verifier(options);
      const actualReason = await reason(v.verifyDsse(bundle, p384.key));
      expect(actualReason).toBe("conflicting-oneof");
    });

    it.each([
      { profile: "strict", options: STRICT },
      { profile: "default", options: DEFAULTS },
    ])("rejects a certificate chain instead of the public key ($profile)", async ({ options }) => {
      const bundle = changed((b) => {
        delete b.verificationMaterial.publicKey;
        b.verificationMaterial.x509CertificateChain = { certificates: [certificate] };
      });
      const v = await verifier(options);
      const actualReason = await reason(v.verifyDsse(bundle, p384.key));
      expect(actualReason).toBe(
        "verification-material-unsupported",
      );
    });

    it.each([
      { profile: "strict", options: STRICT },
      { profile: "default", options: DEFAULTS },
    ])("rejects a certificate instead of the public key ($profile)", async ({ options }) => {
      const bundle = changed((b) => {
        delete b.verificationMaterial.publicKey;
        b.verificationMaterial.certificate = certificate;
      });
      const v = await verifier(options);
      const actualReason = await reason(v.verifyDsse(bundle, p384.key));
      expect(actualReason).toBe(
        "verification-material-unsupported",
      );
    });
  });

  describe("media types", () => {
    it.each([
      { name: "a missing media type", mediaType: undefined },
      { name: "null", mediaType: null },
      { name: "an empty media type", mediaType: "" },
      { name: "legacy v0.1", mediaType: LEGACY_V01 },
      { name: "v0.1", mediaType: CANONICAL_V01 },
      { name: "legacy v0.2", mediaType: LEGACY_V02 },
      { name: "v0.2", mediaType: CANONICAL_V02 },
      { name: "v0.4", mediaType: CANONICAL_V04 },
      { name: "legacy v0.3", mediaType: LEGACY_V03 },
    ])("strict profile rejects $name", async ({ mediaType }) => {
      const v = await verifier();
      const actualReason = await reason(v.verifyDsse(withMediaType(mediaType), p384.key));
      expect(actualReason).toBe(
        "media-type-unsupported",
      );
    });

    it("strict profile accepts the canonical v0.3 media type", async () => {
      const v = await verifier();
      const actualReason = await reason(v.verifyDsse(withMediaType(CANONICAL_V03), p384.key));
      expect(actualReason).toBe("accept");
    });

    // As for certificate bundles: both spellings of v0.2 and v0.3, and not v0.1.
    it.each([
      { name: "legacy v0.3", mediaType: LEGACY_V03, expected: "accept" },
      { name: "v0.2", mediaType: CANONICAL_V02, expected: "accept" },
      { name: "v0.1", mediaType: CANONICAL_V01, expected: "media-type-unsupported" },
    ])("default configuration gives $expected for $name", async ({ mediaType, expected }) => {
      const v = await verifier(DEFAULTS);
      const actualReason = await reason(v.verifyDsse(withMediaType(mediaType), p384.key));
      expect(actualReason).toBe(expected);
    });

    it.each([
      { name: "legacy v0.3", mediaType: LEGACY_V03, expected: "media-type-unsupported" },
      { name: "legacy v0.2", mediaType: LEGACY_V02, expected: "media-type-unsupported" },
      { name: "v0.2", mediaType: CANONICAL_V02, expected: "accept" },
    ])("requireCanonicalMediaType alone gives $expected for $name", async ({ mediaType, expected }) => {
      const v = await verifier(CANONICAL_ONLY);
      const actualReason = await reason(v.verifyDsse(withMediaType(mediaType), p384.key));
      expect(actualReason).toBe(
        expected,
      );
    });
  });

  describe("bundle input", () => {
    it("rejects truncated JSON as bundle-malformed", async () => {
      const v = await verifier();
      const actualReason = await reason(v.verifyDsse(p384.bundle.slice(0, -10), p384.key));
      expect(actualReason).toBe("bundle-malformed");
    });

    it("accepts an already parsed bundle under the strict preset", async () => {
      const v = await verifier();
      await expect(v.verifyDsse(parse(p384), p384.key)).resolves.toBeDefined();
    });

    it("accepts an already parsed bundle by default, as for certificate bundles", async () => {
      const v = await verifier(DEFAULTS);
      await expect(v.verifyDsse(parse(p384), p384.key)).resolves.toBeDefined();
    });
  });

  describe("input size", () => {
    const withLimit = (maxBundleBytes: number) => verifier({ ...STRICT, maxBundleBytes });

    it("rejects text one byte over the limit", async () => {
      const v = await withLimit(p384.bundle.length - 1);
      const actualReason = await reason(v.verifyDsse(p384.bundle, p384.key));
      expect(actualReason).toBe("bundle-too-large");
    });

    it("rejects bytes one byte over the limit", async () => {
      const v = await withLimit(p384.bundle.length - 1);
      const actualReason = await reason(v.verifyDsse(new TextEncoder().encode(p384.bundle), p384.key));
      expect(actualReason).toBe("bundle-too-large");
    });

    it("accepts a bundle of exactly the limit", async () => {
      const v = await withLimit(p384.bundle.length);
      const actualReason = await reason(v.verifyDsse(p384.bundle, p384.key));
      expect(actualReason).toBe("accept");
    });

    // 400 two-byte characters exceed a limit only 100 above the text's UTF-16 length.
    it("counts multi-byte characters as their UTF-8 length", async () => {
      const padded = p384.bundle.replace('"mediaType"', `"x": "${"é".repeat(400)}", "mediaType"`);
      const v = await withLimit(padded.length + 100);
      const actualReason = await reason(v.verifyDsse(padded, p384.key));
      expect(actualReason).toBe("bundle-too-large");
    });

    it("rejects bytes that are not UTF-8 as bundle-malformed", async () => {
      const v = await withLimit(p384.bundle.length - 1);
      const actualReason = await reason(v.verifyDsse(new Uint8Array([0x7b, 0xff, 0x7d]), p384.key));
      expect(actualReason).toBe("bundle-malformed");
    });
  });

  describe("log entry rules", () => {
    const twoEntries = changed((b) => {
      const entries = b.verificationMaterial.tlogEntries;
      entries.push(structuredClone(entries[0]));
    });
    const noEntries = changed((b) => {
      b.verificationMaterial.tlogEntries = [];
    });
    // An entry naming a log outside the trusted root is ignored by default (then too few logs
    // verify), and rejected when checkpoints are bound to the entry's log.
    const unknownLog = changed((b) => {
      b.verificationMaterial.tlogEntries[0].logId.keyId = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    });

    it.each([
      { name: "a second entry", profile: "strict", options: STRICT, bundle: twoEntries, expected: "tlog-entry-count" },
      { name: "a second entry", profile: "default", options: DEFAULTS, bundle: twoEntries, expected: "accept" },
      { name: "no entries", profile: "strict", options: STRICT, bundle: noEntries, expected: "tlog-entry-count" },
      { name: "no entries", profile: "default", options: DEFAULTS, bundle: noEntries, expected: "bundle-malformed" },
      { name: "an unknown log", profile: "strict", options: STRICT, bundle: unknownLog, expected: "tlog-unknown-log" },
      { name: "an unknown log", profile: "default", options: DEFAULTS, bundle: unknownLog, expected: "tlog-threshold" },
    ])("gives $expected for $name ($profile)", async ({ options, bundle, expected }) => {
      const v = await verifier(options);
      const actualReason = await reason(v.verifyDsse(bundle, p384.key));
      expect(actualReason).toBe(expected);
    });
  });

  describe("trusted root", () => {
    it("ignores keys it cannot load when the entry does not need them", async () => {
      const v = await verifier(STRICT, rootWithUnusableKeys());
      const actualReason = await reason(v.verifyDsse(p384.bundle, p384.key));
      expect(actualReason).toBe("accept");
    });

    it("differs from the certificate flow's loader, which rejects that root as a whole", async () => {
      await expect(new SigstoreVerifier().loadSigstoreRoot(rootWithUnusableKeys())).rejects.toThrow();
    });

    it("fails an entry whose log key cannot be loaded", async () => {
      const root = JSON.parse(p384.root);
      const entryLog = root.tlogs.find((l: Json) => l.baseUrl.includes("log2025-1"));
      entryLog.publicKey.rawBytes = "AAAA";

      const v = await verifier(STRICT, root);
      const actualReason = await reason(v.verifyDsse(p384.bundle, p384.key));
      expect(actualReason).toBe("tlog-log-key-unsupported");
    });
  });

  describe("options", () => {
    const numericOptions = ["tlogThreshold", "tsaThreshold", "maxBundleBytes"] as const;
    const invalidNumbers = [-1, 0.5, NaN, Infinity];

    const invalidLimits = numericOptions.flatMap((key) =>
      invalidNumbers.map((value) => ({ key, value })),
    );

    it.each(invalidLimits)(
      "rejects $key = $value",
      ({ key, value }) => {
        expect(() => new ManagedKeyVerifier({ [key]: value })).toThrow("non-negative safe integer");
      },
    );

    it("rejects an empty bundleVersions list", () => {
      expect(() => new ManagedKeyVerifier({ bundleVersions: [] })).toThrow("bundleVersions");
    });

    it("rejects an unknown bundle version", () => {
      expect(() => new ManagedKeyVerifier({ bundleVersions: ["0.4"] })).toThrow("bundleVersions");
    });

    it("freezes the strict profile and its lists", () => {
      expect(Object.isFrozen(STRICT_MANAGED_KEY_PROFILE)).toBe(true);
      expect(Object.isFrozen(STRICT_MANAGED_KEY_PROFILE.bundleVersions)).toBe(true);
      expect(Object.isFrozen(STRICT_MANAGED_KEY_PROFILE.allowedEntryKinds)).toBe(true);
      expect(() => (STRICT_MANAGED_KEY_PROFILE.allowedEntryKinds as string[]).push("dsse/0.0.2")).toThrow(TypeError);
      expect(() => (STRICT_MANAGED_KEY_PROFILE.bundleVersions as string[]).push("0.2")).toThrow(TypeError);
    });

    it("does not see later changes to the lists the caller kept", async () => {
      const bundleVersions = ["0.3"];
      const v = await verifier({ bundleVersions });
      bundleVersions.push("0.2");
      // Without its own copy, the verifier would accept the v0.2-labelled bundle.
      const actualReason = await reason(v.verifyDsse(v02.bundle, v02.key));
      expect(actualReason).toBe("media-type-unsupported");
    });

    it("copies the caller's allowedEntryKinds list", async () => {
      const allowedEntryKinds = ["dsse/0.0.2"];
      const v = await verifier({ allowedEntryKinds });
      allowedEntryKinds.push("hashedrekord/0.0.2");

      const actualReason = await reason(v.verifyDsse(p384.bundle, p384.key));
      expect(actualReason).toBe("tlog-entry-kind");
    });

    it("keeps its own options frozen after construction", async () => {
      const v = await verifier({ ...STRICT_MANAGED_KEY_PROFILE });
      const options = (v as unknown as { options: Record<string, unknown> }).options;
      expect(Object.isFrozen(options)).toBe(true);
      expect(Object.isFrozen(options.bundleVersions)).toBe(true);
      expect(Object.isFrozen(options.allowedEntryKinds)).toBe(true);
      expect(() => {
        options.requireCanonicalMediaType = false;
      }).toThrow(TypeError);
    });

    it("needs a trusted root", async () => {
      const v = new ManagedKeyVerifier();
      const verification = v.verifyDsse(p384.bundle, p384.key);
      await expect(verification).rejects.toThrow("Trusted root is not loaded");
    });
  });

  describe("messageSignature digests", () => {
    it("verifies a real P-384 messageSignature bundle", async () => {
      const { source, artifact } = await messageSignatureFixture("P-384");
      const v = await verifier();
      const actualReason = await reason(v.verifyArtifact(source.bundle, source.key, artifact));
      expect(actualReason).toBe("accept");
    });

    it("verifies a real P-256 messageSignature bundle", async () => {
      const { source, artifact } = await messageSignatureFixture("P-256");
      const v = await verifier();
      const actualReason = await reason(v.verifyArtifact(source.bundle, source.key, artifact));
      expect(actualReason).toBe("accept");
    });

    it("accepts the key's own digest length for digest-only verification", async () => {
      const { source, digest } = await messageSignatureFixture("P-384");
      const v = await verifier({ ...DEFAULTS, verifyDigest: verifySignatureOverDigest });
      const actualReason = await reason(v.verifyArtifact(source.bundle, source.key, digest, true));
      expect(actualReason).toBe("accept");
    });

    it("rejects a 32-byte digest for a P-384 key before calling verifyDigest", async () => {
      const { source, digest } = await messageSignatureFixture("P-384");
      const refuse = () => {
        throw new Error("verifyDigest must not be called");
      };
      const v = await verifier({ ...DEFAULTS, verifyDigest: refuse as never });
      await expect(v.verifyArtifact(source.bundle, source.key, digest.slice(0, 32), true)).rejects.toThrow(
        "SHA-384 digest must be exactly 48 bytes",
      );
    });

    it("rejects a 48-byte digest for a P-256 key", async () => {
      const { source } = await messageSignatureFixture("P-256");
      const v = await verifier({ ...DEFAULTS, verifyDigest: verifySignatureOverDigest });
      await expect(v.verifyArtifact(source.bundle, source.key, new Uint8Array(48), true)).rejects.toThrow(
        "SHA-256 digest must be exactly 32 bytes",
      );
    });

    it("rejects a digest that is the other algorithm's digest of the artifact", async () => {
      const { source, artifact } = await messageSignatureFixture("P-384");
      const sha256 = new Uint8Array(await crypto.subtle.digest("SHA-256", artifact));
      const swapped = JSON.parse(source.bundle);
      swapped.messageSignature.messageDigest.digest = Uint8ArrayToBase64(sha256);
      const v = await verifier();
      const actualReason = await reason(v.verifyArtifact(JSON.stringify(swapped), source.key, artifact));
      expect(actualReason).toBe(
        "artifact-mismatch",
      );
    });

    it("rejects the other algorithm's label even when the digest stays the key's own", async () => {
      const { source, artifact } = await messageSignatureFixture("P-384");
      const swapped = JSON.parse(source.bundle);
      swapped.messageSignature.messageDigest.algorithm = "SHA2_256";
      const v = await verifier();
      const actualReason = await reason(v.verifyArtifact(JSON.stringify(swapped), source.key, artifact));
      expect(actualReason).toBe(
        "artifact-mismatch",
      );
    });

    it("keeps DSSE digest-only verification at 32 bytes for a P-384 key", async () => {
      const v = await verifier();
      await expect(v.verifyArtifact(p384.bundle, p384.key, new Uint8Array(48), true)).rejects.toThrow(
        "SHA-256 digest must be exactly 32 bytes",
      );
    });
  });
});
