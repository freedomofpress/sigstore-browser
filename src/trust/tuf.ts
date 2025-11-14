/*
 * TUF (The Update Framework) integration for trusted root management
 *
 * Provides secure updates for Sigstore trusted root metadata using TUF.
 * Uses tuf-browser for browser-compatible TUF client functionality.
 *
 * Reference: https://github.com/freedomofpress/tuf-browser
 */

import type { TrustedRoot } from "../interfaces.js";
import { Uint8ArrayToString } from "../encoding.js";
import type { TUFClient } from "tuf-browser/dist/tuf.js";

/**
 * Options for TrustedRootProvider configuration
 */
export interface TrustedRootProviderOptions {
  /**
   * TUF repository URL for metadata
   * Default: Sigstore production TUF repository
   */
  metadataUrl?: string;

  /**
   * Target base URL for fetching target files
   * If not specified, uses the same as metadataUrl
   */
  targetBaseUrl?: string;

  /**
   * Initial root metadata (1.root.json content)
   * If not provided, will use embedded default
   */
  initialRoot?: string;

  /**
   * Namespace for TUF cache storage
   * Default: 'sigstore-browser'
   */
  namespace?: string;

  /**
   * Name of the trusted root target file
   * Default: 'trusted_root.json'
   */
  trustedRootTarget?: string;

  /**
   * Cache TTL in milliseconds
   * Default: 1 hour (3600000 ms)
   */
  cacheTTL?: number;
}

/**
 * Default configuration for Sigstore production TUF repository
 */
const DEFAULT_CONFIG = {
  metadataUrl: 'https://tuf-repo-cdn.sigstore.dev/',
  namespace: 'sigstore-browser',
  trustedRootTarget: 'trusted_root.json',
  cacheTTL: 3600000, // 1 hour
};

/**
 * Provides Sigstore trusted root via TUF for secure updates
 *
 * This class manages fetching and caching of Sigstore trusted root metadata
 * using The Update Framework (TUF) for secure, verified updates.
 *
 * Example usage:
 * ```typescript
 * const provider = new TrustedRootProvider();
 * const trustedRoot = await provider.getTrustedRoot();
 * ```
 */
export class TrustedRootProvider {
  private metadataUrl: string;
  private targetBaseUrl?: string;
  private initialRoot?: string;
  private namespace: string;
  private trustedRootTarget: string;
  private cacheTTL: number;

  private tufClient?: TUFClient;
  private cachedRoot?: TrustedRoot;
  private cacheTimestamp?: number;

  constructor(options: TrustedRootProviderOptions = {}) {
    const metadataUrl = options.metadataUrl || DEFAULT_CONFIG.metadataUrl;
    this.metadataUrl = metadataUrl.endsWith('/') ? metadataUrl : `${metadataUrl}/`;
    this.targetBaseUrl = options.targetBaseUrl || this.metadataUrl;
    this.initialRoot = options.initialRoot;
    this.namespace = options.namespace || DEFAULT_CONFIG.namespace;
    this.trustedRootTarget = options.trustedRootTarget || DEFAULT_CONFIG.trustedRootTarget;
    this.cacheTTL = options.cacheTTL ?? DEFAULT_CONFIG.cacheTTL;
  }

  /**
   * Initialize the TUF client
   * Lazy initialization to avoid loading TUF client until needed
   */
  private async initTUFClient(): Promise<void> {
    if (this.tufClient) {
      return;
    }

    try {
      const { TUFClient } = await import('tuf-browser/dist/tuf.js');

      // Get initial root metadata
      const rootMetadata = this.initialRoot || await this.getDefaultRoot();

      this.tufClient = new TUFClient(
        this.metadataUrl,
        rootMetadata,
        this.namespace,
        this.targetBaseUrl
      );
    } catch (error) {
      throw new Error(
        `Failed to initialize TUF client: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Get the default embedded root metadata
   * Returns the TUF root.json that bootstraps the TUF client
   */
  private async getDefaultRoot(): Promise<string> {
    // Import the embedded TUF root metadata (base64-encoded 1.root.json as JSON string)
    // This is the root of trust for TUF, not to be confused with the Sigstore trusted root
    const tufRootModule = await import('./tuf-root.json', { with: { type: 'json' } });
    const tufRootBase64 = tufRootModule.default as string;

    // Decode from base64 to get the actual root.json content
    const decoder = new TextDecoder();
    const rootBytes = Uint8Array.from(atob(tufRootBase64), c => c.charCodeAt(0));
    return decoder.decode(rootBytes);
  }

  /**
   * Check if cached trusted root is still valid
   */
  private isCacheValid(): boolean {
    if (!this.cachedRoot || !this.cacheTimestamp) {
      return false;
    }

    const now = Date.now();
    return (now - this.cacheTimestamp) < this.cacheTTL;
  }

  /**
   * Get the Sigstore trusted root metadata
   * Uses TUF to securely fetch and verify the trusted root
   *
   * @returns Promise<TrustedRoot> The verified trusted root metadata
   * @throws Error if TUF verification fails or root cannot be fetched
   */
  async getTrustedRoot(): Promise<TrustedRoot> {
    // Return cached root if still valid
    if (this.isCacheValid() && this.cachedRoot) {
      return this.cachedRoot;
    }

    // Initialize TUF client if needed
    await this.initTUFClient();

    if (!this.tufClient) {
      throw new Error('TUF client not initialized');
    }

    try {
      // Update TUF metadata (root, timestamp, snapshot, targets)
      // This must be called before getTarget() to populate the metadata cache
      await this.tufClient.updateTUF();

      // Fetch the trusted root target via TUF
      // TUF will handle all verification (signatures, rollback protection, etc.)
      const trustedRootBytes = await this.tufClient.getTarget(this.trustedRootTarget);

      // Parse the trusted root JSON
      const trustedRootJson = Uint8ArrayToString(trustedRootBytes);
      const trustedRoot = JSON.parse(trustedRootJson) as TrustedRoot;

      // Cache the result
      this.cachedRoot = trustedRoot;
      this.cacheTimestamp = Date.now();

      return trustedRoot;
    } catch (error) {
      throw new Error(
        `Failed to fetch trusted root via TUF: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Manually refresh the trusted root from TUF
   * Bypasses cache and forces a fresh fetch
   *
   * @returns Promise<TrustedRoot> The updated trusted root metadata
   */
  async refreshTrustedRoot(): Promise<TrustedRoot> {
    // Clear cache
    this.cachedRoot = undefined;
    this.cacheTimestamp = undefined;

    // Fetch fresh root
    return await this.getTrustedRoot();
  }

  /**
   * Clear the cached trusted root
   * Next call to getTrustedRoot() will fetch fresh data
   */
  clearCache(): void {
    this.cachedRoot = undefined;
    this.cacheTimestamp = undefined;
  }
}
