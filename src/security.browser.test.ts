import { base64ToUint8Array, canonicalize, hexToUint8Array, Uint8ArrayToBase64, Uint8ArrayToHex } from "@freedomofpress/crypto-browser";
import { ed25519 } from "@noble/curves/ed25519.js";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { bundle, digestHex, identity, issuer, trustRoot } from "../test/fixtures/sigstore.js";
import { assertBundle, type TLogEntry } from "./bundle.js";
import type { RawLog } from "./interfaces.js";
import { AllOf, AnyOf } from "./policy.js";
import { SigstoreVerifier, type SigstoreVerifierOptions } from "./sigstore.js";
import { verifyBundleTimestamp } from "./timestamp/tsa.js";
import { X509Certificate } from "./x509/cert.js";

// Keep real timestamp verification by default; individual tests supply already-verified
// timestamps to isolate threshold accounting from the separately tested cryptography.
vi.mock("./timestamp/tsa.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./timestamp/tsa.js")>();
  return { ...actual, verifyBundleTimestamp: vi.fn(actual.verifyBundleTimestamp) };
});

afterEach(() => {
  vi.mocked(verifyBundleTimestamp).mockReset();
  vi.restoreAllMocks();
});

const digest = hexToUint8Array(digestHex);
const signingTime = new Date(Number(bundle().verificationMaterial.tlogEntries[0].integratedTime) * 1000);
const verify = (v: SigstoreVerifier, b = bundle(), data = digest) =>
  v.verifyArtifact(identity, issuer, b, data, true);

async function verifier(options: SigstoreVerifierOptions = {}) {
  const v = new SigstoreVerifier(options);
  await v.loadSigstoreRoot(trustRoot());
  return v;
}

// Real SET signatures over the fixture's body, with independent test log keys.
async function signedLog(): Promise<{ log: RawLog; entry: TLogEntry }> {
  const secret = ed25519.utils.randomSecretKey();
  const spki = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, ...ed25519.getPublicKey(secret)]);
  const logID = new Uint8Array(await crypto.subtle.digest("SHA-256", spki));
  const log: RawLog = {
    baseUrl: "https://log.test",
    hashAlgorithm: "SHA2_256",
    publicKey: { rawBytes: Uint8ArrayToBase64(spki), keyDetails: "PKIX_ED25519", validFor: { start: "2025-01-01T00:00:00Z" } },
    logId: { keyId: Uint8ArrayToBase64(logID) },
  };
  const entry = bundle().verificationMaterial.tlogEntries[0];
  entry.logId = log.logId;
  delete entry.inclusionProof;
  const signed = new TextEncoder().encode(canonicalize({
    body: entry.canonicalizedBody,
    integratedTime: Number(entry.integratedTime),
    logIndex: Number(entry.logIndex),
    logID: Uint8ArrayToHex(logID),
  }));
  entry.inclusionPromise = { signedEntryTimestamp: Uint8ArrayToBase64(ed25519.sign(signed, secret)) };
  return { log, entry };
}

const operatorCases = [
  { name: "anonymous authorities retain threshold-one support", operators: ["", ""], threshold: 1, passes: true },
  { name: "anonymous authorities cannot establish independence", operators: ["", ""], threshold: 2, passes: false },
  { name: "anonymous plus named does not count twice", operators: ["", "a.test"], threshold: 2, passes: false },
  { name: "named plus anonymous does not count twice", operators: ["a.test", ""], threshold: 2, passes: false },
  { name: "multiple keys from one named operator count once", operators: ["a.test", "a.test"], threshold: 2, passes: false },
  { name: "distinct named operators satisfy the threshold", operators: ["a.test", "b.test"], threshold: 2, passes: true },
  { name: "an anonymous authority cannot add a third operator", operators: ["a.test", "", "b.test"], threshold: 3, passes: false },
  { name: "an anonymous authority does not invalidate two named operators", operators: ["a.test", "", "b.test"], threshold: 2, passes: true },
];

describe("Operator thresholds", () => {
  let signedLogs: Awaited<ReturnType<typeof signedLog>>[];
  beforeAll(async () => { signedLogs = await Promise.all([signedLog(), signedLog(), signedLog()]); });

  it.each(operatorCases)("Rekor: $name", async ({ operators, threshold, passes }) => {
    const root = trustRoot();
    root.tlogs = operators.map((operator, i) => ({ ...signedLogs[i].log, operator: operator || undefined }));
    const b = bundle();
    b.mediaType = "application/vnd.dev.sigstore.bundle+json;version=0.1";
    b.verificationMaterial.tlogEntries = operators.map((_, i) => signedLogs[i].entry);
    const v = new SigstoreVerifier({ tlogThreshold: threshold });
    await v.loadSigstoreRoot(root);
    const result = verify(v, b);
    if (passes) await expect(result).resolves.toBe(true);
    else await expect(result).rejects.toThrow("Not enough verified transparency logs");
  });

  it.each(operatorCases)("CT: $name", async ({ operators, threshold, passes }) => {
    const v = await verifier({ ctlogThreshold: threshold });
    // SCT verification itself is covered by the real fixture tests.
    vi.spyOn(v, "verifySCT").mockResolvedValue(new Set(operators));
    const result = verify(v);
    if (passes) await expect(result).resolves.toBe(true);
    else await expect(result).rejects.toThrow("Not enough verified CT log operators");
  });

  it.each(operatorCases)("TSA: $name", async ({ operators, threshold, passes }) => {
    vi.mocked(verifyBundleTimestamp).mockResolvedValue(operators.map((operator) => ({ signingTime, operator })));
    const result = verify(await verifier({ tsaThreshold: threshold }));
    if (passes) await expect(result).resolves.toBe(true);
    else await expect(result).rejects.toThrow("Not enough verified TSA operators");
  });
});

describe("Small input hardening", () => {
  it("awaits asynchronous custom policies and policy combinators", async () => {
    const v = await verifier();
    const rejection = {
      verify: async () => { throw new Error("asynchronous policy rejected"); },
    };

    await expect(v.verifyArtifactPolicy(rejection, bundle(), digest, true))
      .rejects.toThrow("asynchronous policy rejected");
    await expect(v.verifyArtifactPolicy(new AllOf([rejection]), bundle(), digest, true))
      .rejects.toThrow("asynchronous policy rejected");
    await expect(v.verifyArtifactPolicy(new AnyOf([rejection]), bundle(), digest, true))
      .rejects.toThrow("0 of 1 policies succeeded");
  });

  it("rejects malformed authority validity periods while loading the root", async () => {
    for (let i = 0; i < 4; i++) {
      const root = trustRoot();
      const periods = [
        root.tlogs[0].publicKey.validFor,
        root.ctlogs[0].publicKey.validFor,
        root.certificateAuthorities[0].validFor,
        root.timestampAuthorities[0].validFor,
      ];
      periods[i].start = "not-a-date";
      await expect(new SigstoreVerifier().loadSigstoreRoot(root))
        .rejects.toThrow("Invalid authority validity period");
    }

    const root = trustRoot();
    root.tlogs[0].publicKey.validFor = {
      start: "2026-01-02T00:00:00Z",
      end: "2026-01-01T00:00:00Z",
    };
    await expect(new SigstoreVerifier().loadSigstoreRoot(root))
      .rejects.toThrow("Invalid authority validity period");
  });

  it("requires non-negative safe-integer thresholds", () => {
    for (const key of ["tlogThreshold", "ctlogThreshold", "tsaThreshold"] as const) {
      for (const value of [NaN, Infinity, -Infinity, -1, 0.5, Number.MAX_SAFE_INTEGER + 1, "2"]) {
        expect(() => new SigstoreVerifier({ [key]: value } as SigstoreVerifierOptions)).toThrow(`${key} must be a non-negative safe integer`);
      }
      for (const value of [0, 1, 2]) expect(() => new SigstoreVerifier({ [key]: value })).not.toThrow();
    }
  });

  it("rejects digest-only inputs that are not 32 bytes", async () => {
    const v = await verifier();
    for (const length of [0, 31, 33, 64]) {
      await expect(verify(v, bundle(), new Uint8Array(length))).rejects.toThrow("SHA-256 digest must be exactly 32 bytes");
    }
  });

  it("rejects oversized or unrepresentable log numbers before cryptography", () => {
    for (const field of ["logIndex", "integratedTime"] as const) {
      for (const value of ["9".repeat(10000), "9223372036854775808", "-1", "1.5"]) {
        const b = bundle();
        b.verificationMaterial.tlogEntries[0][field] = value;
        expect(() => assertBundle(b)).toThrow("Invalid bundle");
      }
    }
    const unsafe = bundle();
    unsafe.verificationMaterial.tlogEntries[0].logIndex = "9007199254740993";
    expect(() => assertBundle(unsafe)).toThrow("inclusion promise");
    const invalidDate = bundle();
    invalidDate.verificationMaterial.tlogEntries[0].integratedTime = "8640000000001";
    expect(() => assertBundle(invalidDate)).toThrow("integratedTime");
  });

  it("bounds proof integers and sibling counts while preserving full int64 precision", () => {
    for (const field of ["logIndex", "treeSize"] as const) {
      const b = bundle();
      const proof = b.verificationMaterial.tlogEntries[0].inclusionProof;
      if (!proof) throw new Error("Fixture must contain an inclusion proof");
      proof[field] = "9223372036854775808";
      expect(() => assertBundle(b)).toThrow("inclusion proof");
    }
    const b = bundle();
    const entry = b.verificationMaterial.tlogEntries[0];
    const proof = entry.inclusionProof;
    if (!proof) throw new Error("Fixture must contain an inclusion proof");
    delete entry.inclusionPromise;
    entry.logIndex = "9223372036854775806";
    proof.logIndex = entry.logIndex;
    proof.treeSize = "9223372036854775807";
    proof.hashes = Array(63).fill(Uint8ArrayToBase64(new Uint8Array(32)));
    expect(() => assertBundle(b)).not.toThrow();
    proof.hashes.push(proof.hashes[0]);
    expect(() => assertBundle(b)).toThrow("inclusion proof");
  });

  it("enforces the timestamp cap through the exported helper too", async () => {
    await expect(verifyBundleTimestamp({ rfc3161Timestamps: Array(33).fill({ signedTimestamp: "AA==" }) }, digest, []))
      .rejects.toThrow("Invalid bundle: rfc3161Timestamps");
    await expect(verifyBundleTimestamp(undefined, digest, [])).resolves.toEqual([]);
    await expect(verifyBundleTimestamp({}, digest, [])).resolves.toEqual([]);
  });

  it("bounds encoded bundle data and certificate-chain length", async () => {
    const oversized = "A".repeat(16 * 1024 * 1024 + 1);
    const b = bundle();
    if (!b.dsseEnvelope) throw new Error("Fixture must contain a DSSE envelope");
    b.dsseEnvelope.payload = oversized;
    expect(() => assertBundle(b)).toThrow("Invalid bundle");
    await expect(verifyBundleTimestamp(
      { rfc3161Timestamps: [{ signedTimestamp: oversized }] },
      digest,
      [],
    )).rejects.toThrow("Invalid bundle");

    const chained = bundle();
    const cert = chained.verificationMaterial.certificate;
    if (!cert) throw new Error("Fixture must contain a certificate");
    delete chained.verificationMaterial.certificate;
    chained.verificationMaterial.x509CertificateChain = {
      certificates: Array(33).fill(cert),
    };
    expect(() => assertBundle(chained)).toThrow("Invalid bundle: certificate");
  });

  it("rejects malformed or excessive subjects and digest maps", async () => {
    const v = await verifier();
    const b = bundle();
    const cert = b.verificationMaterial.certificate;
    const env = b.dsseEnvelope;
    if (!cert || !env) throw new Error("Fixture must contain a certificate and DSSE envelope");
    const signingCert = X509Certificate.parse(base64ToUint8Array(cert.rawBytes));
    const signature = base64ToUint8Array(env.signatures[0].sig);
    // Isolate parsing of authenticated payloads; the real bundle tests exercise all trust checks.
    vi.spyOn(v as unknown as { verifyBundle: () => Promise<{ signingCert: X509Certificate; signature: Uint8Array }> }, "verifyBundle")
      .mockResolvedValue({ signingCert, signature });
    const subject = { digest: { sha256: digestHex } };
    for (const payload of [null, {}, { subject: [] }, { subject: Array(1025).fill(subject) }]) {
      env.payload = Uint8ArrayToBase64(new TextEncoder().encode(JSON.stringify(payload)));
      await expect(verify(v, b)).rejects.toThrow("DSSE payload must have between 1 and 1024 subjects");
    }
    for (const invalid of [null, { digest: [] }, { digest: Object.fromEntries(Array.from({ length: 33 }, (_, i) => [`hash${i}`, "00"])) }]) {
      env.payload = Uint8ArrayToBase64(new TextEncoder().encode(JSON.stringify({ subject: [invalid, subject] })));
      await expect(verify(v, b)).rejects.toThrow("Invalid DSSE subject digest map");
    }
    env.payload = Uint8ArrayToBase64(new TextEncoder().encode(JSON.stringify({ subject: [{ digest: { sha256: 123 } }] })));
    await expect(verify(v, b)).rejects.toThrow("does not match any subject");
  });
});
