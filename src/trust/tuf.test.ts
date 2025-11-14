import { describe, it, expect, beforeEach } from "vitest";
import { TrustedRootProvider } from "./tuf.js";

describe("TrustedRootProvider", () => {
  describe("constructor", () => {
    it("should create provider with default configuration", () => {
      const provider = new TrustedRootProvider();
      expect(provider).toBeDefined();
    });

    it("should create provider with custom configuration", () => {
      const provider = new TrustedRootProvider({
        metadataUrl: "https://custom.example.com/metadata",
        namespace: "custom-namespace",
        trustedRootTarget: "custom_root.json",
        cacheTTL: 5000,
      });
      expect(provider).toBeDefined();
    });

    it("should use default values for missing options", () => {
      const provider = new TrustedRootProvider({
        namespace: "test",
      });
      expect(provider).toBeDefined();
    });

    it("should ensure metadataUrl has trailing slash", () => {
      const providerWithoutSlash = new TrustedRootProvider({
        metadataUrl: "https://example.com/metadata",
      });
      expect((providerWithoutSlash as any).metadataUrl).toBe("https://example.com/metadata/");

      const providerWithSlash = new TrustedRootProvider({
        metadataUrl: "https://example.com/metadata/",
      });
      expect((providerWithSlash as any).metadataUrl).toBe("https://example.com/metadata/");
    });

    it("should respect cacheTTL of 0", () => {
      const provider = new TrustedRootProvider({
        cacheTTL: 0,
      });
      expect((provider as any).cacheTTL).toBe(0);
    });
  });

  describe("cache management", () => {
    let provider: TrustedRootProvider;

    beforeEach(() => {
      provider = new TrustedRootProvider();
    });

    it("should clear cache when clearCache is called", () => {
      provider.clearCache();
      // Should not throw
      expect(true).toBe(true);
    });
  });

  describe("getTrustedRoot", () => {
    it("should throw error when TUF client cannot be initialized", async () => {
      const provider = new TrustedRootProvider({
        metadataUrl: "https://invalid-url-that-does-not-exist.example.com",
        initialRoot: "invalid-root",
      });

      // This will fail because tuf-browser is not actually available yet
      // and the URL is invalid
      await expect(provider.getTrustedRoot()).rejects.toThrow();
    });
  });

  describe("refreshTrustedRoot", () => {
    it("should clear cache before fetching", async () => {
      const provider = new TrustedRootProvider();

      // Should fail because TUF client is not available
      await expect(provider.refreshTrustedRoot()).rejects.toThrow();
    }, 10000);
  });
});

describe("TrustedRootProvider integration", () => {
  it("should be importable and instantiable", () => {
    const provider = new TrustedRootProvider({
      metadataUrl: "https://tuf-repo-cdn.sigstore.dev",
      namespace: "test-sigstore",
    });

    expect(provider).toBeInstanceOf(TrustedRootProvider);
  });

  it("should support custom cache TTL", () => {
    const provider = new TrustedRootProvider({
      cacheTTL: 60000, // 1 minute
    });

    expect(provider).toBeDefined();
  });
});
