import { describe, it, expect } from "vitest";
import { verifyTLogBody } from "./body.js";
import { base64Encode } from "../encoding.js";
import type { SigstoreBundle, TLogEntry } from "../bundle.js";

const createTestBundle = (): SigstoreBundle => ({
  mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.1",
  verificationMaterial: {
    certificate: {
      rawBytes:
        "MIICoDCCAiagAwIBAgIUevae+nLQ8mg6OyOB43MKJ10F2CEwCgYIKoZIzj0EAwMwNzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRlcm1lZGlhdGUwHhcNMjIxMTA5MDEzMzA5WhcNMjIxMTA5MDE0MzA5WjAAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9DbYBIMQLtWb6J5gtL69jgRwwEfdtQtKvvG4+o3ZzlOroJplpXaVgF6wBDob++rNG9/AzSaBmApkEwI52XBjWqOCAUUwggFBMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUVIIFc08z6uV9Y96S+v5oDbbmHEYwHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0RAQH/BBUwE4ERYnJpYW5AZGVoYW1lci5jb20wLAYKKwYBBAGDvzABAQQeaHR0cHM6Ly9naXRodWIuY29tL2xvZ2luL29hdXRoMIGKBgorBgEEAdZ5AgQCBHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGEWgUGQwAABAMARzBFAiEAlKycMBC2q+QM+mct60RNENxpURHes6vgOBWdx71XcXgCIAtnMzw/cBw5h0hrYJ8b1PJjoxn3k1N2TdgofqvMhbSTMAoGCCqGSM49BAMDA2gAMGUCMQC2KLFYSiD/+S1WEsyf9czf52w+E577Hi77r8pGUM1rQ/Bzg1aGvQs0/kAg3S/JSDgCMEdN5dIS0tRm1SOMbOFcW+1yzR+OiCVJ7DVFwUdI3D/7ERxtN9e/LJ6uaRnR/Sanrw==",
    },
    tlogEntries: [],
  },
  messageSignature: {
    messageDigest: {
      algorithm: "SHA2_256",
      digest: "aOZWslHmfoNYvvhIOrDVHGYZ8+ehqfDnWDjUH/No9yg=",
    },
    signature:
      "MEQCIHs5aUulq1HpR+fwmSKpLk/oAwq5O9CDNFHhZAKfG5GmAiBwcVnf2obzsCGVlf0AIvbvHr21NXt7tpLBl4+Brh6OKA==",
  },
});

const createValidHashedRekordEntry = (): TLogEntry => ({
  logIndex: "6757503",
  logId: { keyId: "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0=" },
  kindVersion: { kind: "hashedrekord", version: "0.0.1" },
  integratedTime: "1667957590",
  canonicalizedBody:
    "eyJhcGlWZXJzaW9uIjoiMC4wLjEiLCJraW5kIjoiaGFzaGVkcmVrb3JkIiwic3BlYyI6eyJkYXRhIjp7Imhhc2giOnsiYWxnb3JpdGhtIjoic2hhMjU2IiwidmFsdWUiOiI2OGU2NTZiMjUxZTY3ZTgzNThiZWY4NDgzYWIwZDUxYzY2MTlmM2U3YTFhOWYwZTc1ODM4ZDQxZmYzNjhmNzI4In19LCJzaWduYXR1cmUiOnsiY29udGVudCI6Ik1FUUNJSHM1YVV1bHExSHBSK2Z3bVNLcExrL29Bd3E1TzlDRE5GSGhaQUtmRzVHbUFpQndjVm5mMm9ienNDR1ZsZjBBSXZidkhyMjFOWHQ3dHBMQmw0K0JyaDZPS0E9PSIsInB1YmxpY0tleSI6eyJjb250ZW50IjoiTFMwdExTMUNSVWRKVGlCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2sxSlNVTnZSRU5EUVdsaFowRjNTVUpCWjBsVlpYWmhaU3R1VEZFNGJXYzJUM2xQUWpRelRVdEtNVEJHTWtORmQwTm5XVWxMYjFwSmVtb3dSVUYzVFhjS1RucEZWazFDVFVkQk1WVkZRMmhOVFdNeWJHNWpNMUoyWTIxVmRWcEhWakpOVWpSM1NFRlpSRlpSVVVSRmVGWjZZVmRrZW1SSE9YbGFVekZ3WW01U2JBcGpiVEZzV2tkc2FHUkhWWGRJYUdOT1RXcEplRTFVUVRWTlJFVjZUWHBCTlZkb1kwNU5ha2w0VFZSQk5VMUVSVEJOZWtFMVYycEJRVTFHYTNkRmQxbElDa3R2V2tsNmFqQkRRVkZaU1V0dldrbDZhakJFUVZGalJGRm5RVVU1UkdKWlFrbE5VVXgwVjJJMlNqVm5kRXcyT1dwblVuZDNSV1prZEZGMFMzWjJSelFLSzI4elducHNUM0p2U25Cc2NGaGhWbWRHTm5kQ1JHOWlLeXR5VGtjNUwwRjZVMkZDYlVGd2EwVjNTVFV5V0VKcVYzRlBRMEZWVlhkblowWkNUVUUwUndwQk1WVmtSSGRGUWk5M1VVVkJkMGxJWjBSQlZFSm5UbFpJVTFWRlJFUkJTMEpuWjNKQ1owVkdRbEZqUkVGNlFXUkNaMDVXU0ZFMFJVWm5VVlZXU1VsR0NtTXdPSG8yZFZZNVdUazJVeXQyTlc5RVltSnRTRVZaZDBoM1dVUldVakJxUWtKbmQwWnZRVlV6T1ZCd2VqRlphMFZhWWpWeFRtcHdTMFpYYVhocE5Ga0tXa1E0ZDBoM1dVUldVakJTUVZGSUwwSkNWWGRGTkVWU1dXNUtjRmxYTlVGYVIxWnZXVmN4YkdOcE5XcGlNakIzVEVGWlMwdDNXVUpDUVVkRWRucEJRZ3BCVVZGbFlVaFNNR05JVFRaTWVUbHVZVmhTYjJSWFNYVlpNamwwVERKNGRsb3liSFZNTWpsb1pGaFNiMDFKUjB0Q1oyOXlRbWRGUlVGa1dqVkJaMUZEQ2tKSWQwVmxaMEkwUVVoWlFUTlVNSGRoYzJKSVJWUktha2RTTkdOdFYyTXpRWEZLUzFoeWFtVlFTek12YURSd2VXZERPSEEzYnpSQlFVRkhSVmRuVlVjS1VYZEJRVUpCVFVGU2VrSkdRV2xGUVd4TGVXTk5Ra015Y1N0UlRTdHRZM1EyTUZKT1JVNTRjRlZTU0dWek5uWm5UMEpYWkhnM01WaGpXR2REU1VGMGJncE5lbmN2WTBKM05XZ3dhSEpaU2poaU1WQkthbTk0YmpOck1VNHlWR1JuYjJaeGRrMW9ZbE5VVFVGdlIwTkRjVWRUVFRRNVFrRk5SRUV5WjBGTlIxVkRDazFSUXpKTFRFWlpVMmxFTHl0VE1WZEZjM2xtT1dONlpqVXlkeXRGTlRjM1NHazNOM0k0Y0VkVlRURnlVUzlDZW1jeFlVZDJVWE13TDJ0Qlp6TlRMMG9LVTBSblEwMUZaRTQxWkVsVE1IUlNiVEZUVDAxaVQwWmpWeXN4ZVhwU0swOXBRMVpLTjBSV1JuZFZaRWt6UkM4M1JWSjRkRTQ1WlM5TVNqWjFZVkp1VWdvdlUyRnVjbmM5UFFvdExTMHRMVVZPUkNCRFJWSlVTVVpKUTBGVVJTMHRMUzB0Q2c9PSJ9fX19",
});

describe("verifyTLogBody", () => {
  describe("with valid hashedrekord entry", () => {
    it("should verify without throwing", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      await expect(verifyTLogBody(entry, bundle)).resolves.toBeUndefined();
    });
  });

  describe("with kind/version mismatch", () => {
    it("should throw when kind in kindVersion doesn't match body", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      entry.kindVersion.kind = "dsse";

      await expect(verifyTLogBody(entry, bundle)).rejects.toThrow(
        "kind/version mismatch"
      );
    });

    it("should throw when version in kindVersion doesn't match body", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      entry.kindVersion.version = "0.0.99";

      await expect(verifyTLogBody(entry, bundle)).rejects.toThrow(
        "kind/version mismatch"
      );
    });
  });

  describe("with invalid canonicalizedBody", () => {
    it("should throw when canonicalizedBody is not valid base64", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      entry.canonicalizedBody = "not-valid-base64!@#$%";

      await expect(verifyTLogBody(entry, bundle)).rejects.toThrow(
        "Failed to parse canonicalized body"
      );
    });

    it("should throw when canonicalizedBody is not valid JSON", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      entry.canonicalizedBody = base64Encode("not valid json");

      await expect(verifyTLogBody(entry, bundle)).rejects.toThrow(
        "Failed to parse canonicalized body"
      );
    });

    it("should throw when body is missing required fields", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      entry.canonicalizedBody = base64Encode('{"kind": "hashedrekord"}');

      await expect(verifyTLogBody(entry, bundle)).rejects.toThrow(
        "Invalid Rekor entry structure"
      );
    });
  });

  describe("with unsupported entry kinds", () => {
    it("should throw for dsse entries", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      entry.kindVersion.kind = "dsse";
      entry.canonicalizedBody = base64Encode(
        JSON.stringify({
          apiVersion: "0.0.1",
          kind: "dsse",
          spec: { signature: {} },
        })
      );

      await expect(verifyTLogBody(entry, bundle)).rejects.toThrow(
        "Bundle missing dsseEnvelope for DSSE entry"
      );
    });

    it("should throw for intoto entries", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      entry.kindVersion.kind = "intoto";
      entry.canonicalizedBody = base64Encode(
        JSON.stringify({
          apiVersion: "0.0.1",
          kind: "intoto",
          spec: { signature: {} },
        })
      );

      await expect(verifyTLogBody(entry, bundle)).rejects.toThrow(
        "Unsupported intoto version: 0.0.1"
      );
    });
  });
});
