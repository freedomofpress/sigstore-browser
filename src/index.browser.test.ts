import { describe, it, expect } from "vitest";
import { SigstoreVerifier } from "./sigstore.js";

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
