import {
  base64ToUint8Array,
  hexToUint8Array,
  Uint8ArrayToBase64,
  Uint8ArrayToHex,
} from "@freedomofpress/crypto-browser";
import { describe, expect, it } from "vitest";

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

async function verifier(opts: SigstoreVerifierOptions = {}, root: TrustedRoot = trustRoot()) {
  const v = new SigstoreVerifier(opts);
  await v.loadSigstoreRoot(root);
  return v;
}

async function verify(b: SigstoreBundle, opts: SigstoreVerifierOptions = {}, root?: TrustedRoot) {
  return (await verifier(opts, root)).verifyArtifact(identity, issuer, b, digest, true);
}

// Builds a DER SEQUENCE chain `depth` levels deep around an empty OCTET STRING.
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

const signingCertB64 = () => bundle().verificationMaterial.certificate?.rawBytes ?? "";
const signingCert = () => X509Certificate.parse(base64ToUint8Array(signingCertB64()));

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
    await expect(v.verifyArtifact(identity, issuer, bundle(), new Uint8Array(32), true)).rejects.toThrow(
      "does not match any subject",
    );
  });
});

describe("Fix 1: tlog threshold counts distinct fully verified logs", () => {
  const withExtraEntries = (make: (e: TLogEntry, i: number) => TLogEntry, count: number) => {
    const b = bundle();
    const [first] = b.verificationMaterial.tlogEntries;
    for (let i = 1; i <= count; i++) b.verificationMaterial.tlogEntries.push(make(structuredClone(first), i));
    return b;
  };

  it("rejects when the bundle has fewer verified entries than the threshold", async () => {
    await expect(verify(bundle(), { tlogThreshold: 2 })).rejects.toThrow("Not enough verified tlog entries: 1 < 2");
  });

  it("rejects duplicate entries that carry neither an inclusion proof nor a promise", async () => {
    const b = withExtraEntries((e, i) => {
      e.logIndex = String(Number(e.logIndex) + i);
      delete e.inclusionProof;
      delete e.inclusionPromise;
      return e;
    }, 1);
    await expect(verify(b, { tlogThreshold: 2 })).rejects.toThrow("requires an inclusion proof");
  });

  it("verifies the SET of every entry, so a copied entry with a forged logIndex fails", async () => {
    const b = withExtraEntries((e, i) => {
      e.logIndex = String(Number(e.logIndex) + i);
      return e;
    }, 1);
    await expect(verify(b, { tlogThreshold: 2 })).rejects.toThrow("inclusion promise");
  });

  it("does not count entries from logs missing in the trusted root", async () => {
    const unknown = (e: TLogEntry, i: number) => {
      e.logId = { keyId: Uint8ArrayToBase64(new Uint8Array(32).fill(i)) };
      delete e.inclusionProof;
      delete e.inclusionPromise;
      return e;
    };
    await expect(verify(withExtraEntries(unknown, 3), { tlogThreshold: 4 })).rejects.toThrow(
      "Not enough verified tlog entries: 1 < 4",
    );
    const b = bundle();
    b.verificationMaterial.tlogEntries[0].logId = { keyId: Uint8ArrayToBase64(new Uint8Array(32)) };
    await expect(verify(b)).rejects.toThrow("Not enough verified tlog entries: 0 < 1");
  });

  it("rejects more than 32 entries", async () => {
    await expect(verify(withExtraEntries((e) => e, 32))).rejects.toThrow("Too many tlog entries");
  });
});

describe("Fix 2: every tlog entry kind and version binds the logged certificate", () => {
  const pem = (b64: string) =>
    Uint8ArrayToBase64(new TextEncoder().encode(`-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`));
  const otherDer = trustRoot().certificateAuthorities[1].certChain.certificates[0].rawBytes;
  const otherPem = pem(otherDer);
  const ownPem = pem(signingCertB64());
  const env = bundle().dsseEnvelope ?? { payload: "", payloadType: "", signatures: [{ sig: "" }] };
  const sig = env.signatures[0].sig;
  const hashHex = () =>
    crypto.subtle
      .digest("SHA-256", base64ToUint8Array(env.payload) as BufferSource)
      .then((h) => Uint8ArrayToHex(new Uint8Array(h)));

  const entry = (kind: string, version: string, spec: unknown): TLogEntry => ({
    logIndex: "1",
    logId: { keyId: trustRoot().tlogs[0].logId.keyId },
    kindVersion: { kind, version },
    integratedTime: "1",
    canonicalizedBody: Uint8ArrayToBase64(new TextEncoder().encode(JSON.stringify({ apiVersion: version, kind, spec }))),
  });

  it("dsse 0.0.1 and 0.0.2", async () => {
    const h = await hashHex();
    const hB64 = Uint8ArrayToBase64(hexToUint8Array(h));
    const v1 = (verifier?: string) =>
      entry("dsse", "0.0.1", { payloadHash: { algorithm: "sha256", value: h }, signatures: [{ signature: sig, verifier }] });
    const v2 = (rawBytes?: string) =>
      entry("dsse", "0.0.2", {
        dsseV002: {
          payloadHash: { algorithm: "SHA2_256", digest: hB64 },
          signatures: [{ content: sig, verifier: rawBytes ? { x509Certificate: { rawBytes } } : undefined }],
        },
      });
    await expect(verifyTLogBody(v1(ownPem), bundle(), signingCert())).resolves.toBeUndefined();
    await expect(verifyTLogBody(v2(signingCertB64()), bundle(), signingCert())).resolves.toBeUndefined();
    for (const bad of [v1(otherPem), v2(otherDer)]) {
      await expect(verifyTLogBody(bad, bundle(), signingCert())).rejects.toThrow("does not match the signing certificate");
    }
    for (const missing of [v1(undefined), v2(undefined)]) {
      await expect(verifyTLogBody(missing, bundle(), signingCert())).rejects.toThrow("does not record the signing certificate");
    }
  });

  it("intoto 0.0.2", async () => {
    const h = await hashHex();
    const doubleB64 = Uint8ArrayToBase64(new TextEncoder().encode(sig));
    const e = (publicKey?: string) =>
      entry("intoto", "0.0.2", {
        content: {
          envelope: { payload: "", payloadType: "", signatures: [{ sig: doubleB64, publicKey }] },
          payloadHash: { algorithm: "sha256", value: h },
        },
      });
    await expect(verifyTLogBody(e(ownPem), bundle(), signingCert())).resolves.toBeUndefined();
    await expect(verifyTLogBody(e(otherPem), bundle(), signingCert())).rejects.toThrow("does not match");
    await expect(verifyTLogBody(e(undefined), bundle(), signingCert())).rejects.toThrow("does not record");
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
        hashedRekordV002: {
          data: { algorithm: "SHA2_256", digest: "AA==" },
          signature: { content: sig, verifier: rawBytes ? { x509Certificate: { rawBytes } } : undefined },
        },
      });
    await expect(verifyTLogBody(v1(ownPem), hr, signingCert())).resolves.toBeUndefined();
    await expect(verifyTLogBody(v2(signingCertB64()), hr, signingCert())).resolves.toBeUndefined();
    await expect(verifyTLogBody(v1(otherPem), hr, signingCert())).rejects.toThrow("does not match");
    await expect(verifyTLogBody(v2(otherDer), hr, signingCert())).rejects.toThrow("does not match");
    await expect(verifyTLogBody(v1(undefined), hr, signingCert())).rejects.toThrow("does not record");
    await expect(verifyTLogBody(v2(undefined), hr, signingCert())).rejects.toThrow("does not record");
  });
});

describe("Fix 3: bundle media type and structure", () => {
  const proofless = (mediaType: string) => {
    const b = bundle();
    b.mediaType = mediaType;
    delete b.verificationMaterial.tlogEntries[0].inclusionProof;
    return b;
  };

  it("rejects unknown media types instead of treating them as v0.1", async () => {
    for (const mt of ["application/x-garbage", "APPLICATION/VND.DEV.SIGSTORE.BUNDLE.V0.3+JSON", ""]) {
      await expect(verify(proofless(mt))).rejects.toThrow("Unsupported bundle media type");
    }
  });

  it("requires an inclusion proof for v0.2+ but accepts a SET-only v0.1 bundle", async () => {
    await expect(verify(proofless("application/vnd.dev.sigstore.bundle.v0.3+json"))).rejects.toThrow("requires an inclusion proof");
    await expect(verify(proofless("application/vnd.dev.sigstore.bundle+json;version=0.1"))).resolves.toBe(true);
  });

  it("rejects a bundle carrying both a message signature and a DSSE envelope", async () => {
    const b = bundle() as unknown as Record<string, unknown>;
    b.messageSignature = { messageDigest: { algorithm: "SHA2_256", digest: "AA==" }, signature: "AA==" };
    await expect(verify(b as unknown as SigstoreBundle)).rejects.toThrow("exactly one of messageSignature or dsseEnvelope");
  });

  it("verifyDsse rejects non-dsse entries", async () => {
    const b = bundle();
    b.verificationMaterial.tlogEntries[0].kindVersion.kind = "hashedrekord";
    await expect((await verifier()).verifyDsse(b, policy)).rejects.toThrow("Expected entry type dsse");
  });
});

describe("Fixes 4 and 5: strict, depth-bounded DER", () => {
  const withCert = (der: Uint8Array) => {
    const b = bundle();
    b.verificationMaterial.certificate = { rawBytes: Uint8ArrayToBase64(der) };
    return b;
  };

  it("rejects a signing certificate with trailing bytes", async () => {
    const der = base64ToUint8Array(signingCertB64());
    await expect(verify(withCert(new Uint8Array([...der, 0xde, 0xad])))).rejects.toThrow("Invalid DER encoding");
  });

  it("rejects a signing certificate with a non-minimal BER length", async () => {
    const der = base64ToUint8Array(signingCertB64());
    await expect(verify(withCert(new Uint8Array([0x30, 0x83, 0x00, ...der.subarray(2)])))).rejects.toThrow("Invalid DER encoding");
  });

  it("rejects deeply nested certificates and timestamps without exhausting the stack", async () => {
    const deep = nested(8000);
    expect(deep.length).toBeGreaterThan(24_000);
    await expect(verify(withCert(deep))).rejects.toThrow("nesting too deep");
    expect(() => RFC3161Timestamp.parse(deep)).toThrow("nesting too deep");
    expect(() => RFC3161Timestamp.parse(new Uint8Array([...nested(3), 0x00]))).toThrow("Invalid DER encoding");
  });
});

describe("Fix 6: observer timestamps and historical trust material", () => {
  const integratedTime = new Date(Number(bundle().verificationMaterial.tlogEntries[0].integratedTime) * 1000);
  const laterThanSigning = new Date(integratedTime.getTime() + 24 * 3600 * 1000).toISOString();

  it("verifies against a CA or Rekor key that was retired after the signature was made", async () => {
    const ca = trustRoot();
    ca.certificateAuthorities[1].validFor.end = laterThanSigning;
    await expect(verify(bundle(), {}, ca)).resolves.toBe(true);
    const log = trustRoot();
    log.tlogs[0].publicKey.validFor.end = laterThanSigning;
    await expect(verify(bundle(), {}, log)).resolves.toBe(true);
  });

  it("checks the CA validity window at the observer time, not at the leaf notBefore", async () => {
    const root = trustRoot();
    root.certificateAuthorities[1].validFor.start = laterThanSigning;
    await expect(verify(bundle(), {}, root)).rejects.toThrow("No valid CAs found");
  });

  it("requires at least one verified observer timestamp", async () => {
    // Without a SET the integrated time is unauthenticated, and there is no TSA timestamp either.
    const b = bundle();
    delete b.verificationMaterial.tlogEntries[0].inclusionPromise;
    await expect(verify(b)).rejects.toThrow("No verified observer timestamp");
    const v2 = bundle();
    delete v2.verificationMaterial.tlogEntries[0].inclusionPromise;
    v2.verificationMaterial.tlogEntries[0].integratedTime = null;
    v2.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: [] };
    await expect(verify(v2)).rejects.toThrow("No verified observer timestamp");
  });

  it("loads all trust material regardless of the wall clock", async () => {
    const root = trustRoot();
    expect(root.certificateAuthorities.some((ca) => ca.validFor.end && new Date(ca.validFor.end) < new Date())).toBe(true);
    const v = await verifier({}, root);
    expect(v.loadCA(root.certificateAuthorities)).toHaveLength(root.certificateAuthorities.length);
    expect(await v.loadLog(root.tlogs)).toHaveLength(root.tlogs.length);
  });
});
