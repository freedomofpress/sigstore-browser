import { describe, it, expect } from "vitest";
import { SigstoreVerifier } from "./sigstore.js";
import { X509Certificate } from "./x509/cert.js";

describe("Sigstore Browser Integration Tests", () => {
  it("should initialize SigstoreVerifier in browser", () => {
    const verifier = new SigstoreVerifier();
    expect(verifier).toBeDefined();
    expect(verifier).toBeInstanceOf(SigstoreVerifier);
  });

  it("should have crypto.subtle available for ECDSA P-256 verification", async () => {
    expect(globalThis.crypto).toBeDefined();
    expect(globalThis.crypto.subtle).toBeDefined();

    // Test ECDSA P-256 which is what Sigstore uses
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

    const data = new TextEncoder().encode("test");
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      data
    );

    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.publicKey,
      signature,
      data
    );

    expect(valid).toBe(true);
  });

  it("should have crypto.subtle available for ECDSA P-384 verification", async () => {
    // Test ECDSA P-384 which is also used by Sigstore
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-384",
      },
      true,
      ["sign", "verify"]
    );

    const data = new TextEncoder().encode("test");
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-384" },
      keyPair.privateKey,
      data
    );

    const valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-384" },
      keyPair.publicKey,
      signature,
      data
    );

    expect(valid).toBe(true);
  });

  it("should support SHA-256 hashing in browser", async () => {
    const data = new TextEncoder().encode("test data");
    const hash = await crypto.subtle.digest("SHA-256", data);

    expect(hash).toBeInstanceOf(ArrayBuffer);
    expect(hash.byteLength).toBe(32);
  });

  it("should support SHA-384 hashing in browser", async () => {
    const data = new TextEncoder().encode("test data");
    const hash = await crypto.subtle.digest("SHA-384", data);

    expect(hash).toBeInstanceOf(ArrayBuffer);
    expect(hash.byteLength).toBe(48);
  });

  it("should support SHA-512 hashing in browser", async () => {
    const data = new TextEncoder().encode("test data");
    const hash = await crypto.subtle.digest("SHA-512", data);

    expect(hash).toBeInstanceOf(ArrayBuffer);
    expect(hash.byteLength).toBe(64);
  });

  it("should support X.509 certificate key import (SPKI format)", async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "ECDSA",
        namedCurve: "P-256",
      },
      true,
      ["sign", "verify"]
    );

    const exported = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const imported = await crypto.subtle.importKey(
      "spki",
      exported,
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["verify"]
    );

    expect(imported).toBeDefined();
    expect(imported.type).toBe("public");
  });

  it("should support RSA-PSS for signature verification", async () => {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"]
    );

    const data = new TextEncoder().encode("test");
    const signature = await crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      keyPair.privateKey,
      data
    );

    const valid = await crypto.subtle.verify(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      keyPair.publicKey,
      signature,
      data
    );

    expect(valid).toBe(true);
  });

  it("should verify RSA-PSS signed X.509 certificate", async () => {
    // Self-signed certificate with standard RSA key but RSA-PSS signature (SHA-256, salt=32)
    // WebCrypto requires rsaEncryption OID for the public key, not id-RSASSA-PSS
    const rsaPssCertPem = `-----BEGIN CERTIFICATE-----
MIIDhTCCAjmgAwIBAgIUYzfguLRx71Cbn2Ty7xCt3GH+N6AwQQYJKoZIhvcNAQEK
MDSgDzANBglghkgBZQMEAgEFAKEcMBoGCSqGSIb3DQEBCDANBglghkgBZQMEAgEF
AKIDAgEgMB4xHDAaBgNVBAMME1Rlc3QgUlNBLVBTUyBTaWduZWQwHhcNMjUxMTMw
MDMwMDU2WhcNMjYxMTMwMDMwMDU2WjAeMRwwGgYDVQQDDBNUZXN0IFJTQS1QU1Mg
U2lnbmVkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA29B/88QFBILg
YCWp1pF3xBj7FVhBUCv6JwyZAouYWUxgGmpFg6RLgbaWk59oDtEFQ5xRGSDXLuMW
GL5wZVCjSnmYcBsBDROO+HfLKwDRcHw09bJY979PDHPy5EPZale/JsdxE+fepUw1
XQDvlK5Dyp6WKl9UBjTtl6+LHKV/KTo+SiaQP2vsbZvTIt3s8MHybV/ixYXlSPQt
Kju50REAaqSSYqxNzsq8Z2sjJbFBcatt5C1JhfoSyIHz5D0slriv8835DYhk0u4n
bvNzXhWeF7htHTiPWCYwaTr5cgjyhEWg3SNP+Tu9dxCYVXm7/jWTHRdPqUPQqFsq
wXqsrzSP+wIDAQABo1MwUTAdBgNVHQ4EFgQU+UcBxKusOtY4lSjqyFuxQfN5zdIw
HwYDVR0jBBgwFoAU+UcBxKusOtY4lSjqyFuxQfN5zdIwDwYDVR0TAQH/BAUwAwEB
/zBBBgkqhkiG9w0BAQowNKAPMA0GCWCGSAFlAwQCAQUAoRwwGgYJKoZIhvcNAQEI
MA0GCWCGSAFlAwQCAQUAogMCASADggEBAFIn3VpfydVvpI82NwfeGxWlhZhgD2dX
gJUhj6pcXqwnlCzpyRI4e3uNO1h9nr9UrogI0AV2IDhVdUYxz3F2/680JtxXpB1x
J02BSAYllvXgf9efc20lFzbPDzvMzKnwx3S3proewbJ4uVPHzvKubWsx8MwEuI0X
8xkI1qMIXgevTCt+LGhp+0C/u8WsW3or5ZI7GnZNowPJEAtZnfO+VORB7FvbzEGr
ewS+2T7Qz4oXaQMidPOjr1Q8WKqaKO4yCtC8cz4qVWi3lNqAcAGtonQMXUiflEWV
9kqKQx+LJYJqxKkBtDRnRLnVNn4+inotrgnV126LsCe3uLaGwJIFy1U=
-----END CERTIFICATE-----`;

    const cert = X509Certificate.parse(rsaPssCertPem);

    // Verify it's an RSA-PSS certificate
    expect(cert.signatureAlgorithmOid).toBe("1.2.840.113549.1.1.10");
    expect(cert.signatureAlgorithm).toBe("sha256");

    // Verify the self-signed certificate (signature verification)
    const valid = await cert.verify();
    expect(valid).toBe(true);
  });

  it("should support TextEncoder/TextDecoder for UTF-8", () => {
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    const text = "Hello Sigstore 🔐";
    const encoded = encoder.encode(text);
    const decoded = decoder.decode(encoded);

    expect(decoded).toBe(text);
    expect(encoded).toBeInstanceOf(Uint8Array);
  });

  it("should support base64 encoding/decoding (atob/btoa)", () => {
    const text = "Hello Sigstore";
    const base64 = btoa(text);
    const decoded = atob(base64);

    expect(decoded).toBe(text);
    expect(base64).toBe("SGVsbG8gU2lnc3RvcmU=");
  });

  it("should support Uint8Array operations", () => {
    const arr1 = new Uint8Array([1, 2, 3, 4, 5]);
    const arr2 = new Uint8Array([6, 7, 8, 9, 10]);

    const combined = new Uint8Array(arr1.length + arr2.length);
    combined.set(arr1, 0);
    combined.set(arr2, arr1.length);

    expect(combined.length).toBe(10);
    expect(combined[0]).toBe(1);
    expect(combined[5]).toBe(6);
  });

  it("should support ArrayBuffer operations", () => {
    const buffer = new ArrayBuffer(32);
    const view = new Uint8Array(buffer);

    view[0] = 255;
    view[31] = 128;

    expect(buffer.byteLength).toBe(32);
    expect(view[0]).toBe(255);
    expect(view[31]).toBe(128);
  });

  it("should support DataView for byte manipulation", () => {
    const buffer = new ArrayBuffer(8);
    const view = new DataView(buffer);

    view.setUint32(0, 0x12345678, false); // big-endian
    view.setUint32(4, 0x9abcdef0, false);

    expect(view.getUint32(0, false)).toBe(0x12345678);
    expect(view.getUint8(0)).toBe(0x12);
    expect(view.getUint8(1)).toBe(0x34);
  });

  it("should support JSON parsing of complex structures", () => {
    const json = '{"mediaType":"application/vnd.dev.sigstore.bundle+json;version=0.3","verificationMaterial":{"tlogEntries":[{"logIndex":"123"}]}}';
    const parsed = JSON.parse(json);

    expect(parsed.mediaType).toBeDefined();
    expect(parsed.verificationMaterial).toBeDefined();
    expect(parsed.verificationMaterial.tlogEntries).toBeInstanceOf(Array);
    expect(parsed.verificationMaterial.tlogEntries[0].logIndex).toBe("123");
  });
});
