import { describe, it, expect, vi, beforeEach } from "vitest";
import { verifyRFC3161Timestamp, verifyBundleTimestamp } from "./tsa.js";
import { RFC3161Timestamp } from "../rfc3161/index.js";
import { base64Encode } from "../encoding.js";
import type { RawTimestampAuthority } from "../interfaces.js";
import * as x509 from "../x509/cert.js";
import * as crypto from "../crypto.js";

describe("TSA Timestamp Verification", () => {
  describe("verifyRFC3161Timestamp", () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    it("should verify a valid timestamp with matching authority", async () => {
      const mockPublicKey = {} as CryptoKey;

      const mockCert = {
        serialNumber: new Uint8Array([1, 2, 3]),
        issuer: new Uint8Array([4, 5, 6]),
        validForDate: vi.fn().mockReturnValue(true),
        verify: vi.fn().mockResolvedValue(true),
        publicKeyObj: Promise.resolve(mockPublicKey),
      };

      vi.spyOn(x509.X509Certificate, "parse").mockReturnValue(mockCert as any);
      vi.spyOn(crypto, "bufferEqual").mockImplementation((a: Uint8Array, b: Uint8Array) => {
        if (a.length !== b.length) return false;
        for (let i = 0; i < a.length; i++) {
          if (a[i] !== b[i]) return false;
        }
        return true;
      });

      const mockTimestamp = {
        signingTime: new Date("2024-01-01T00:00:00Z"),
        signerSerialNumber: new Uint8Array([1, 2, 3]),
        signerIssuer: new Uint8Array([4, 5, 6]),
        verify: vi.fn().mockResolvedValue(undefined),
      } as unknown as RFC3161Timestamp;

      const mockCA: RawTimestampAuthority = {
        subject: {
          organization: "Test Org",
          commonName: "Test CA",
        },
        certChain: {
          certificates: [
            {
              rawBytes: base64Encode(new Uint8Array([1, 2, 3])),
            },
          ],
        },
        validFor: {
          start: "2023-01-01T00:00:00Z",
          end: "2025-01-01T00:00:00Z",
        },
      };

      const data = new Uint8Array([10, 11, 12]);
      const signingTime = await verifyRFC3161Timestamp(
        mockTimestamp,
        data,
        [mockCA]
      );

      expect(signingTime).toEqual(new Date("2024-01-01T00:00:00Z"));
      expect(mockTimestamp.verify).toHaveBeenCalledWith(
        data,
        mockPublicKey
      );
    });

    it("should throw error when no authorities match", async () => {
      const mockTimestamp = {
        signingTime: new Date("2024-01-01T00:00:00Z"),
        signerSerialNumber: new Uint8Array([1, 2, 3]),
        signerIssuer: new Uint8Array([4, 5, 6]),
        verify: vi.fn(),
      } as unknown as RFC3161Timestamp;

      const mockCA: RawTimestampAuthority = {
        subject: {
          organization: "Test Org",
          commonName: "Test CA",
        },
        certChain: {
          certificates: [],
        },
        validFor: {
          start: "2023-01-01T00:00:00Z",
          end: "2025-01-01T00:00:00Z",
        },
      };

      const data = new Uint8Array([10, 11, 12]);

      await expect(
        verifyRFC3161Timestamp(mockTimestamp, data, [mockCA])
      ).rejects.toThrow("Timestamp could not be verified against any trusted authority");
    });

    it("should filter out authorities not valid at signing time", async () => {
      const mockTimestamp = {
        signingTime: new Date("2022-01-01T00:00:00Z"),
        signerSerialNumber: new Uint8Array([1, 2, 3]),
        signerIssuer: new Uint8Array([4, 5, 6]),
        verify: vi.fn(),
      } as unknown as RFC3161Timestamp;

      const mockCA: RawTimestampAuthority = {
        subject: {
          organization: "Test Org",
          commonName: "Test CA",
        },
        certChain: {
          certificates: [
            {
              rawBytes: base64Encode(new Uint8Array([1, 2, 3])),
            },
          ],
        },
        validFor: {
          start: "2023-01-01T00:00:00Z",
          end: "2025-01-01T00:00:00Z",
        },
      };

      const data = new Uint8Array([10, 11, 12]);

      await expect(
        verifyRFC3161Timestamp(mockTimestamp, data, [mockCA])
      ).rejects.toThrow("Timestamp could not be verified against any trusted authority");
    });
  });

  describe("verifyBundleTimestamp", () => {
    it("should return undefined when no timestamps present", async () => {
      const result = await verifyBundleTimestamp(
        {},
        new Uint8Array(),
        []
      );
      expect(result).toBeUndefined();
    });

    it("should verify and return timestamp from bundle data", async () => {
      const mockPublicKey = {} as CryptoKey;

      const mockCert = {
        serialNumber: new Uint8Array([1, 2, 3]),
        issuer: new Uint8Array([4, 5, 6]),
        validForDate: vi.fn().mockReturnValue(true),
        verify: vi.fn().mockResolvedValue(true),
        publicKeyObj: Promise.resolve(mockPublicKey),
      };

      vi.spyOn(x509.X509Certificate, "parse").mockReturnValue(mockCert as any);
      vi.spyOn(crypto, "bufferEqual").mockReturnValue(true);

      const mockTimestampData = {
        rfc3161Timestamps: [
          {
            signedTimestamp: base64Encode(new Uint8Array([1, 2, 3, 4])),
          },
        ],
      };

      const mockParsedTimestamp = {
        signingTime: new Date("2024-01-01T00:00:00Z"),
        signerSerialNumber: new Uint8Array([1, 2, 3]),
        signerIssuer: new Uint8Array([4, 5, 6]),
        verify: vi.fn().mockResolvedValue(undefined),
      } as unknown as RFC3161Timestamp;

      vi.spyOn(RFC3161Timestamp, "parse").mockReturnValue(mockParsedTimestamp);

      const mockCA: RawTimestampAuthority = {
        subject: {
          organization: "Test Org",
          commonName: "Test CA",
        },
        certChain: {
          certificates: [
            {
              rawBytes: base64Encode(new Uint8Array([1, 2, 3])),
            },
          ],
        },
        validFor: {
          start: "2023-01-01T00:00:00Z",
          end: "2025-01-01T00:00:00Z",
        },
      };

      const signature = new Uint8Array([10, 11, 12]);
      const result = await verifyBundleTimestamp(
        mockTimestampData,
        signature,
        [mockCA]
      );

      expect(result).toEqual(new Date("2024-01-01T00:00:00Z"));
    });

    it("should throw error when no valid timestamps found", async () => {
      const mockTimestampData = {
        rfc3161Timestamps: [
          {
            signedTimestamp: base64Encode(new Uint8Array([255])), // Invalid
          },
        ],
      };

      // Mock parse to throw
      vi.spyOn(RFC3161Timestamp, "parse").mockImplementation(() => {
        throw new Error("Invalid timestamp");
      });

      await expect(
        verifyBundleTimestamp(mockTimestampData, new Uint8Array(), [])
      ).rejects.toThrow("No valid RFC3161 timestamps found");
    });
  });
});