import { describe, it, expect } from "vitest";
import { verifyHashedRekordBody } from "./hashedrekord.js";
import type { SigstoreBundle } from "../bundle.js";
import type { RekorEntry } from "./body.js";

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

const createValidHashedRekordEntry = (): RekorEntry => ({
  apiVersion: "0.0.1",
  kind: "hashedrekord",
  spec: {
    data: {
      hash: {
        algorithm: "sha256",
        value:
          "68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728",
      },
    },
    signature: {
      content:
        "MEQCIHs5aUulq1HpR+fwmSKpLk/oAwq5O9CDNFHhZAKfG5GmAiBwcVnf2obzsCGVlf0AIvbvHr21NXt7tpLBl4+Brh6OKA==",
      publicKey: {
        content:
          "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNvRENDQWlhZ0F3SUJBZ0lVZXZhZStuTFE4bWc2T3lPQjQzTUtKMTBGMkNFd0NnWUlLb1pJemowRUF3TXcKTnpFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUjR3SEFZRFZRUURFeFZ6YVdkemRHOXlaUzFwYm5SbApjbTFsWkdsaGRHVXdIaGNOTWpJeE1UQTVNREV6TXpBNVdoY05Nakl4TVRBNU1ERTBNRE01V2pBQU1Ga3dFd1lICktvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUU5RGJZQklNUUx0V2I2SjVndEw2OWpnUnd3RWZkdFF0S3Z2RzQKK28zWnpsT3JvSnBscFhhVmdGNndCRG9iKytyTkc5L0F6U2FCbUFwa0V3STUyWEJqV3FPQ0FVVXdnZ0ZCTUFJR0ExVWREd0VCL3dRRUF3SUhnREFUQmdOVkhTVUVEREFLQmdnckJnRUZCUWNEQXpBZEJnTlZIUTRFRmdRVVZJSUYKYzA4ejZ1VjlZOTZTK3Y1b0RiYm1IRVl3SHdZRFZSMGpCQmd3Rm9BVTM5UHB6MVlrRVpiNXFOanBLRldpeGk0WQpaRDh3SHdZRFZSMFJBUUgvQkJVd0U0RVJZbkpwWVc1QVpHVm9ZVzFsY2k1amIyMHdMQVlLS3dZQkJBR0R2ekFCCkFRUWVhSFIwY0hNNkx5OW5hWFJvZFdJdVkyOXRMMnh2WjJsdkwyOWhkWFJvTUlHS0Jnb3JCZ0VFQWRaNUFnUUMKQkh3RWVnQjRBSFlBM1Qwd2FzYkhFVEpqR1I0Y21XYzNBcUpLWHJqZVBLMy9oNHB5Z0M4cDdvNEFBQUdFV2dVRwpRd0FBQkFNQVJ6QkZBaUVBbEt5Y01CQzJxK1FNK21jdDYwUk5FTnhwVVJIZXM2dmdPQldkeDcxWGNYZ0NJQXRuCk16dy9jQnc1aDBocllKOGIxUEpqb3huM2sxTjJUZGdvZnF2TWhiU1RNQW9HQ0NxR1NNNDlCQU1EQTJnQU1HVUMKTVFDMktMRllTaUQvK1MxV0VzeWY5Y3pmNTJ3K0U1NzdIaTc3cjhwR1VNMXJRL0J6ZzFhR3ZRczAva0FnM1MvSgpTRGdDTUVkTjVkSVMwdFJtMVNPTWJPRmNXKzF5elIrT2lDVko3RFZGd1VkSTNELzdFUnh0TjllL0xKNnVhUm5SL1Nhbnc9PQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==",
      },
    },
  },
});

describe("verifyHashedRekordBody", () => {
  describe("with valid v0.0.1 entry", () => {
    it("should verify without throwing", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      await expect(
        verifyHashedRekordBody(entry, bundle)
      ).resolves.toBeUndefined();
    });
  });

  describe("with unsupported version", () => {
    it("should throw for unsupported version", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();
      (entry as any).apiVersion = "0.0.99";

      await expect(verifyHashedRekordBody(entry, bundle)).rejects.toThrow(
        "Unsupported hashedrekord version: 0.0.99"
      );
    });
  });

  describe("with missing messageSignature", () => {
    it("should throw when bundle has no messageSignature", async () => {
      const bundle = createTestBundle();
      bundle.messageSignature = undefined;
      const entry = createValidHashedRekordEntry();

      await expect(verifyHashedRekordBody(entry, bundle)).rejects.toThrow(
        "Bundle missing messageSignature"
      );
    });
  });

  describe("with signature mismatch", () => {
    it("should throw when signatures don't match", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      bundle.messageSignature!.signature = "bWlzbWF0Y2hlZCBzaWduYXR1cmU=";

      await expect(verifyHashedRekordBody(entry, bundle)).rejects.toThrow(
        "Signature mismatch"
      );
    });

    it("should throw when signature is missing from entry", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      (entry.spec as any).signature.content = "";

      await expect(verifyHashedRekordBody(entry, bundle)).rejects.toThrow(
        "Signature mismatch"
      );
    });
  });

  describe("with digest mismatch", () => {
    it("should throw when digests don't match", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      (entry.spec as any).data.hash.value =
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

      await expect(verifyHashedRekordBody(entry, bundle)).rejects.toThrow(
        "Digest mismatch"
      );
    });

    it("should throw when digest is missing from entry", async () => {
      const bundle = createTestBundle();
      const entry = createValidHashedRekordEntry();

      (entry.spec as any).data.hash.value = "";

      await expect(verifyHashedRekordBody(entry, bundle)).rejects.toThrow(
        "Digest mismatch"
      );
    });
  });

});
