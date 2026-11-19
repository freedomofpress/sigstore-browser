import { base64ToUint8Array, Uint8ArrayToBase64 } from "@freedomofpress/crypto-browser";
import { describe, expect, it } from "vitest";

import * as rekor2 from "../test/fixtures/rekor2.js";
import * as rekor2Dsse from "../test/fixtures/rekor2-dsse.js";
import * as keyless from "../test/fixtures/sigstore.js";
import { reason } from "../test/helpers.ts";
import { REASON_CODES } from "./errors.js";
import { RFC3161Timestamp } from "./rfc3161/index.js";
import { verifyTLogBody } from "./tlog/body.js";
import { X509Certificate } from "./x509/index.js";

// Fixture bundles are parsed JSON that tests change freely.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Json = any;

const certificateOf = (bundle: Json) =>
  X509Certificate.parse(base64ToUint8Array(bundle.verificationMaterial.certificate.rawBytes));

const otherBytes = (b64: string) => {
  const bytes = base64ToUint8Array(b64);
  bytes[bytes.length - 1] ^= 1;
  return Uint8ArrayToBase64(bytes);
};

describe("REASON_CODES", () => {
  it("lists each reason code once", () => {
    expect(new Set(REASON_CODES).size).toBe(REASON_CODES.length);
  });
});

describe("transparency log body checks in the certificate flow", () => {
  // A dsse 0.0.1 entry logged under a Fulcio certificate.
  const verifyDsseEntry = (change: (bundle: Json) => void = () => {}) => {
    const bundle: Json = keyless.bundle();
    change(bundle);
    const [entry] = bundle.verificationMaterial.tlogEntries;
    return reason(verifyTLogBody(entry, bundle, certificateOf(keyless.bundle())));
  };

  // A hashedrekord 0.0.2 entry from a Rekor v2 log, over a message signature.
  const verifyHashedRekordEntry = (change: (bundle: Json) => void = () => {}) => {
    const bundle: Json = rekor2.bundle();
    change(bundle);
    const [entry] = bundle.verificationMaterial.tlogEntries;
    return reason(verifyTLogBody(entry, bundle, certificateOf(rekor2.bundle())));
  };

  it("accepts the unchanged dsse and hashedrekord entries", async () => {
    expect(await verifyDsseEntry()).toBe("accept");
    expect(await verifyHashedRekordEntry()).toBe("accept");
  });

  it("reports a DSSE signature that differs from the logged one as tlog-signature-mismatch", async () => {
    const code = await verifyDsseEntry((b) => {
      b.dsseEnvelope.signatures[0].sig = otherBytes(b.dsseEnvelope.signatures[0].sig);
    });
    expect(code).toBe("tlog-signature-mismatch");
  });

  it("reports a DSSE payload that differs from the logged hash as tlog-digest-mismatch", async () => {
    const code = await verifyDsseEntry((b) => {
      b.dsseEnvelope.payload = otherBytes(b.dsseEnvelope.payload);
    });
    expect(code).toBe("tlog-digest-mismatch");
  });

  it("reports a message signature that differs from the logged one as tlog-signature-mismatch", async () => {
    const code = await verifyHashedRekordEntry((b) => {
      b.messageSignature.signature = otherBytes(b.messageSignature.signature);
    });
    expect(code).toBe("tlog-signature-mismatch");
  });

  it("reports a message digest that differs from the logged one as tlog-digest-mismatch", async () => {
    const code = await verifyHashedRekordEntry((b) => {
      b.messageSignature.messageDigest.digest = otherBytes(b.messageSignature.messageDigest.digest);
    });
    expect(code).toBe("tlog-digest-mismatch");
  });

  it("reports an entry whose kind or version differs from its body as tlog-entry-malformed", async () => {
    const code = await verifyDsseEntry((b) => {
      b.verificationMaterial.tlogEntries[0].kindVersion.version = "0.0.2";
    });
    expect(code).toBe("tlog-entry-malformed");
  });

  it("reports a body that is not base64 JSON as tlog-entry-malformed", async () => {
    const code = await verifyDsseEntry((b) => {
      b.verificationMaterial.tlogEntries[0].canonicalizedBody = "not a body";
    });
    expect(code).toBe("tlog-entry-malformed");
  });
});

describe("RFC 3161 timestamp checks", () => {
  // The fixture's timestamp covers its DSSE signature and was issued by the first certificate of
  // the trusted root's timestamp authority; the second is that authority's root.
  const bundle: Json = rekor2Dsse.bundle();
  const root: Json = rekor2Dsse.trustRoot();
  const [token] = bundle.verificationMaterial.timestampVerificationData.rfc3161Timestamps;
  const timestamp = () => RFC3161Timestamp.parse(base64ToUint8Array(token.signedTimestamp));
  const signature = base64ToUint8Array(bundle.dsseEnvelope.signatures[0].sig);
  const authorityCertificates = root.timestampAuthorities[0].certChain.certificates;
  const parsedCertificates = authorityCertificates.map((certificate: { rawBytes: string }) => {
    const bytes = base64ToUint8Array(certificate.rawBytes);
    return X509Certificate.parse(bytes);
  });
  const [issuer, authorityRoot] = parsedCertificates;

  it("accepts the timestamp over the signature it covers, with its issuer's key", async () => {
    expect(await reason(timestamp().verify(signature, await issuer.publicKeyObj))).toBe("accept");
  });

  it("reports a timestamp over another message as timestamp-message-mismatch", async () => {
    const other = new Uint8Array(signature);
    other[0] ^= 1;
    expect(await reason(timestamp().verify(other, await issuer.publicKeyObj))).toBe("timestamp-message-mismatch");
  });

  it("reports a signature that another key does not verify as timestamp-signature-invalid", async () => {
    expect(await reason(timestamp().verify(signature, await authorityRoot.publicKeyObj))).toBe(
      "timestamp-signature-invalid",
    );
  });
});
