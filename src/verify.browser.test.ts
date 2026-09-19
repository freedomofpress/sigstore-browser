import { base64ToUint8Array, hexToUint8Array, Uint8ArrayToBase64, Uint8ArrayToHex } from "@freedomofpress/crypto-browser";
import { describe, expect, it } from "vitest";

import * as rekor2 from "../test/fixtures/rekor2.js";
import { bundle, digestHex, identity, issuer, trustRoot } from "../test/fixtures/sigstore.js";
import type { SigstoreBundle, TLogEntry } from "./bundle.js";
import type { TrustedRoot } from "./interfaces.js";
import { AllOf, AnyOf, Identity, OIDCIssuer, OIDCIssuerV2 } from "./policy.js";
import { RFC3161Timestamp } from "./rfc3161/index.js";
import { SigstoreVerifier, type SigstoreVerifierOptions } from "./sigstore.js";
import { verifyTLogBody } from "./tlog/body.js";
import { X509Certificate } from "./x509/cert.js";

const digest = hexToUint8Array(digestHex);
const policy = new AllOf([new Identity({ identity }), new AnyOf([new OIDCIssuerV2(issuer), new OIDCIssuer(issuer)])]);
const signingCertB64 = () => bundle().verificationMaterial.certificate?.rawBytes ?? "";
const signingCert = () => X509Certificate.parse(base64ToUint8Array(signingCertB64()));
const integratedTime = new Date(Number(bundle().verificationMaterial.tlogEntries[0].integratedTime) * 1000);
const dayAfterSigning = new Date(integratedTime.getTime() + 86_400_000).toISOString();

async function verifier(opts: SigstoreVerifierOptions = {}, root: TrustedRoot = trustRoot()) {
  const v = new SigstoreVerifier(opts);
  await v.loadSigstoreRoot(root);
  return v;
}
const verify = async (b: SigstoreBundle, opts: SigstoreVerifierOptions = {}, root?: TrustedRoot) =>
  (await verifier(opts, root)).verifyArtifact(identity, issuer, b, digest, true);

// Wraps an empty OCTET STRING in `depth` SEQUENCEs with minimal DER lengths.
function nested(depth: number): Uint8Array {
  let buf = new Uint8Array([0x04, 0x00]);
  for (let i = 0; i < depth; i++) {
    const len = buf.length;
    const hdr = len < 128 ? [0x30, len] : len < 256 ? [0x30, 0x81, len] : [0x30, 0x82, len >> 8, len & 0xff];
    const next = new Uint8Array(hdr.length + len);
    next.set(hdr);
    next.set(buf, hdr.length);
    buf = next;
  }
  return buf;
}

describe("Baseline", () => {
  it("verifies the fixture bundle with verifyArtifact and verifyDsse", async () => {
    await expect(verify(bundle())).resolves.toBe(true);
    const result = await (await verifier()).verifyDsse(bundle(), policy);
    expect(result.payloadType).toBe("application/vnd.in-toto+json");
    expect(new TextDecoder().decode(result.payload)).toContain(digestHex);
  });

  it("rejects a wrong identity and a wrong artifact digest", async () => {
    const v = await verifier();
    await expect(v.verifyArtifact("someone@else", issuer, bundle(), digest, true)).rejects.toThrow();
    await expect(v.verifyArtifact(identity, issuer, bundle(), new Uint8Array(32), true)).rejects.toThrow("does not match any subject");
  });
});

describe("Transparency log entries and threshold", () => {
  const withExtra = (make: (e: TLogEntry, i: number) => TLogEntry, count: number) => {
    const b = bundle();
    const [first] = b.verificationMaterial.tlogEntries;
    for (let i = 1; i <= count; i++) b.verificationMaterial.tlogEntries.push(make(structuredClone(first), i));
    return b;
  };
  const proofless = (e: TLogEntry, i: number) => {
    e.logIndex = String(Number(e.logIndex) + i);
    delete e.inclusionProof;
    delete e.inclusionPromise;
    return e;
  };

  it("counts distinct verified log operators against the threshold", async () => {
    await expect(verify(bundle(), { tlogThreshold: 2 })).rejects.toThrow("Not enough verified transparency logs: 1 < 2");
    await expect(verify(withExtra(proofless, 1), { tlogThreshold: 2 })).rejects.toThrow("requires an inclusion proof");
    const unknown = (e: TLogEntry, i: number) => proofless({ ...e, logId: { keyId: Uint8ArrayToBase64(new Uint8Array(32).fill(i)) } }, i);
    await expect(verify(withExtra(unknown, 3), { tlogThreshold: 4 })).rejects.toThrow("Not enough verified transparency logs: 1 < 4");
    const b = bundle();
    b.verificationMaterial.tlogEntries[0].logId = { keyId: Uint8ArrayToBase64(new Uint8Array(32)) };
    await expect(verify(b)).rejects.toThrow("Not enough verified transparency logs: 0 < 1");
  });

  it("verifies the SET of every entry, so a copied entry with a forged logIndex fails", async () => {
    const forged = (e: TLogEntry, i: number) => ({ ...e, logIndex: String(Number(e.logIndex) + i) });
    await expect(verify(withExtra(forged, 1), { tlogThreshold: 2 })).rejects.toThrow("inclusion promise");
  });

  it("groups logs by operator and never infers independence from missing metadata", async () => {
    const root = trustRoot();
    expect(root.tlogs.every((t) => t.operator === undefined)).toBe(true);
    const keys = await (await verifier()).loadLog(root.tlogs);
    expect(new Set(keys.map((k) => k.operator)).size).toBe(1);
    root.tlogs.forEach((t, i) => (t.operator = `operator-${i}`));
    expect(new Set((await (await verifier()).loadLog(root.tlogs)).map((k) => k.operator)).size).toBe(2);
    await expect(verify(bundle(), {}, root)).resolves.toBe(true);
  });

  it("requires the Rekor key to be valid at the integrated time", async () => {
    const expired = trustRoot();
    expired.tlogs[0].publicKey.validFor.end = new Date(integratedTime.getTime() - 1000).toISOString();
    await expect(verify(bundle(), {}, expired)).rejects.toThrow("Rekor key was not valid at the integrated time");
    const future = trustRoot();
    future.tlogs[0].publicKey.validFor.start = dayAfterSigning;
    await expect(verify(bundle(), {}, future)).rejects.toThrow("Rekor key was not valid at the integrated time");
  });

  it("rejects more than 32 entries", async () => {
    await expect(verify(withExtra((e) => e, 32))).rejects.toThrow("Invalid bundle: tlogEntries");
  });
});

describe("Logged certificate binding per entry kind and version", () => {
  const pem = (b64: string) => Uint8ArrayToBase64(new TextEncoder().encode(`-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`));
  const otherDer = trustRoot().certificateAuthorities[1].certChain.certificates[0].rawBytes;
  const otherPem = pem(otherDer);
  const ownPem = pem(signingCertB64());
  const env = bundle().dsseEnvelope ?? { payload: "", payloadType: "", signatures: [{ sig: "" }] };
  const sig = env.signatures[0].sig;
  const hashHex = () =>
    crypto.subtle.digest("SHA-256", base64ToUint8Array(env.payload) as BufferSource).then((h) => Uint8ArrayToHex(new Uint8Array(h)));
  const entry = (kind: string, version: string, spec: unknown): TLogEntry => ({
    logIndex: "1",
    logId: { keyId: trustRoot().tlogs[0].logId.keyId },
    kindVersion: { kind, version },
    integratedTime: "1",
    canonicalizedBody: Uint8ArrayToBase64(new TextEncoder().encode(JSON.stringify({ apiVersion: version, kind, spec }))),
  });
  const expectBinding = async (ok: TLogEntry, wrong: TLogEntry, missing: TLogEntry, b: SigstoreBundle) => {
    await expect(verifyTLogBody(ok, b, signingCert())).resolves.toBeUndefined();
    await expect(verifyTLogBody(wrong, b, signingCert())).rejects.toThrow("does not match the signing certificate");
    await expect(verifyTLogBody(missing, b, signingCert())).rejects.toThrow("does not record the signing certificate");
  };

  it("dsse 0.0.1 and 0.0.2", async () => {
    const h = await hashHex();
    const v1 = (verifier?: string) => entry("dsse", "0.0.1", { payloadHash: { algorithm: "sha256", value: h }, signatures: [{ signature: sig, verifier }] });
    const v2 = (rawBytes?: string) =>
      entry("dsse", "0.0.2", {
        dsseV002: {
          payloadHash: { algorithm: "SHA2_256", digest: Uint8ArrayToBase64(hexToUint8Array(h)) },
          signatures: [{ content: sig, verifier: rawBytes ? { x509Certificate: { rawBytes } } : undefined }],
        },
      });
    await expectBinding(v1(ownPem), v1(otherPem), v1(undefined), bundle());
    await expectBinding(v2(signingCertB64()), v2(otherDer), v2(undefined), bundle());
  });

  it("intoto 0.0.2", async () => {
    const h = await hashHex();
    const doubleB64 = Uint8ArrayToBase64(new TextEncoder().encode(sig));
    const e = (publicKey?: string) =>
      entry("intoto", "0.0.2", {
        content: { envelope: { payload: "", payloadType: "", signatures: [{ sig: doubleB64, publicKey }] }, payloadHash: { algorithm: "sha256", value: h } },
      });
    await expectBinding(e(ownPem), e(otherPem), e(undefined), bundle());
  });

  it("hashedrekord 0.0.1 and 0.0.2", async () => {
    const b = bundle() as unknown as Record<string, unknown>;
    delete b.dsseEnvelope;
    b.messageSignature = { messageDigest: { algorithm: "SHA2_256", digest: "AA==" }, signature: sig };
    const hr = b as unknown as SigstoreBundle;
    const v1 = (content?: string) =>
      entry("hashedrekord", "0.0.1", { data: { hash: { algorithm: "sha256", value: "00" } }, signature: { content: sig, publicKey: { content } } });
    const v2 = (rawBytes?: string) =>
      entry("hashedrekord", "0.0.2", {
        hashedRekordV002: { data: { algorithm: "SHA2_256", digest: "AA==" }, signature: { content: sig, verifier: rawBytes ? { x509Certificate: { rawBytes } } : undefined } },
      });
    await expectBinding(v1(ownPem), v1(otherPem), v1(undefined), hr);
    await expectBinding(v2(signingCertB64()), v2(otherDer), v2(undefined), hr);
  });
});

describe("Bundle media type and structure", () => {
  const proofless = (mediaType: string) => {
    const b = bundle();
    b.mediaType = mediaType;
    delete b.verificationMaterial.tlogEntries[0].inclusionProof;
    return b;
  };

  it("accepts only bundle versions 0.1 to 0.3", async () => {
    for (const mt of ["application/x-garbage", "APPLICATION/VND.DEV.SIGSTORE.BUNDLE.V0.3+JSON", "", "application/vnd.dev.sigstore.bundle.v0.4+json", "application/vnd.dev.sigstore.bundle.v1.0+json"]) {
      await expect(verify(proofless(mt))).rejects.toThrow("Unsupported bundle media type");
    }
    await expect(verify(proofless("application/vnd.dev.sigstore.bundle.v0.3+json"))).rejects.toThrow("requires an inclusion proof");
    await expect(verify(proofless("application/vnd.dev.sigstore.bundle+json;version=0.1"))).resolves.toBe(true);
  });

  it("rejects a bundle carrying both a message signature and a DSSE envelope", async () => {
    const b = bundle() as unknown as Record<string, unknown>;
    b.messageSignature = { messageDigest: { algorithm: "SHA2_256", digest: "AA==" }, signature: "AA==" };
    await expect(verify(b as unknown as SigstoreBundle)).rejects.toThrow("exactly one of messageSignature or dsseEnvelope");
  });

  it("rejects DSSE payload types other than in-toto and non-dsse entries in verifyDsse", async () => {
    const b = bundle();
    if (b.dsseEnvelope) b.dsseEnvelope.payloadType = "application/json";
    await expect(verify(b)).rejects.toThrow("Unsupported DSSE payload type");
    const c = bundle();
    c.verificationMaterial.tlogEntries[0].kindVersion.kind = "hashedrekord";
    await expect((await verifier()).verifyDsse(c, policy)).rejects.toThrow(/kind\/version mismatch|Expected entry type dsse/);
  });
});

describe("Strict DER from crypto-browser", () => {
  const withCert = (der: Uint8Array) => {
    const b = bundle();
    b.verificationMaterial.certificate = { rawBytes: Uint8ArrayToBase64(der) };
    return b;
  };

  it("rejects trailing bytes, BER lengths and deep nesting in certificates and timestamps", async () => {
    const der = base64ToUint8Array(signingCertB64());
    await expect(verify(withCert(new Uint8Array([...der, 0xde, 0xad])))).rejects.toThrow("trailing bytes");
    await expect(verify(withCert(new Uint8Array([0x30, 0x83, 0x00, ...der.subarray(2)])))).rejects.toThrow("non-minimal length");
    const deep = nested(8000);
    await expect(verify(withCert(deep))).rejects.toThrow("nesting too deep");
    expect(() => RFC3161Timestamp.parse(deep)).toThrow("nesting too deep");
  });
});

describe("Observer timestamps and historical trust material", () => {
  it("verifies against a CA or Rekor key that was retired after the signature was made", async () => {
    const ca = trustRoot();
    ca.certificateAuthorities[1].validFor.end = dayAfterSigning;
    await expect(verify(bundle(), {}, ca)).resolves.toBe(true);
    const log = trustRoot();
    log.tlogs[0].publicKey.validFor.end = dayAfterSigning;
    await expect(verify(bundle(), {}, log)).resolves.toBe(true);
  });

  it("checks the CA validity window at the observer time", async () => {
    const root = trustRoot();
    root.certificateAuthorities[1].validFor.start = dayAfterSigning;
    await expect(verify(bundle(), {}, root)).rejects.toThrow("No valid CAs found");
  });

  it("requires at least one verified observer timestamp", async () => {
    // Without a SET the integrated time is unauthenticated, and there is no TSA timestamp either.
    const b = bundle();
    delete b.verificationMaterial.tlogEntries[0].inclusionPromise;
    await expect(verify(b)).rejects.toThrow("No verified observer timestamp");
  });

  it("loads all trust material regardless of the wall clock", async () => {
    const root = trustRoot();
    expect(root.certificateAuthorities.some((ca) => ca.validFor.end && new Date(ca.validFor.end) < new Date())).toBe(true);
    const v = await verifier({}, root);
    expect(v.loadCA(root.certificateAuthorities)).toHaveLength(root.certificateAuthorities.length);
    expect(await v.loadLog(root.tlogs)).toHaveLength(root.tlogs.length);
  });
});

describe("Rekor v2 bundle with RFC 3161 timestamp", () => {
  const r2digest = base64ToUint8Array(rekor2.digestB64);
  const verifyR2 = async (b: SigstoreBundle, data = r2digest, opts: SigstoreVerifierOptions = {}) =>
    (await verifier(opts, rekor2.trustRoot())).verifyArtifact(rekor2.identity, rekor2.issuer, b, data, true);

  it("verifies hashedrekord 0.0.2, an Ed25519 checkpoint and a real TSA response", async () => {
    await expect(verifyR2(rekor2.bundle())).resolves.toBe(true);
    await expect(verifyR2(rekor2.bundle(), r2digest, { tsaThreshold: 1 })).resolves.toBe(true);
    await expect(verifyR2(rekor2.bundle(), r2digest, { tsaThreshold: 2 })).rejects.toThrow("Not enough verified TSA operators: 1 < 2");
  });

  it("needs the timestamp as its only observer time and matches the message digest to the artifact", async () => {
    const b = rekor2.bundle();
    delete b.verificationMaterial.timestampVerificationData;
    await expect(verifyR2(b)).rejects.toThrow("No verified observer timestamp");
    await expect(verifyR2(rekor2.bundle(), new Uint8Array(32))).rejects.toThrow("does not match the bundle message digest");
  });

  it("rejects a tampered timestamp and a swapped signing certificate", async () => {
    const b = rekor2.bundle();
    const ts = b.verificationMaterial.timestampVerificationData?.rfc3161Timestamps[0];
    if (ts) ts.signedTimestamp = Uint8ArrayToBase64(new Uint8Array([...base64ToUint8Array(ts.signedTimestamp), 0]));
    await expect(verifyR2(b)).rejects.toThrow("trailing bytes");
    const c = rekor2.bundle();
    c.verificationMaterial.certificate = bundle().verificationMaterial.certificate;
    await expect(verifyR2(c)).rejects.toThrow();
  });
});
