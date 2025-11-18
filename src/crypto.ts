import { ASN1Obj } from "./asn1/index.js";
import {
  base64ToUint8Array,
  base64UrlToUint8Array,
  hexToUint8Array,
  toArrayBuffer,
  Uint8ArrayToHex,
} from "./encoding.js";
import { EcdsaTypes, HashAlgorithms, KeyTypes } from "./interfaces.js";
import { toDER } from "./pem.js";
import { p256, p384, p521 } from "@noble/curves/nist.js";

function pkcs1ToSpki(pkcs1Bytes: Uint8Array): Uint8Array {
  const algorithmIdentifier = new Uint8Array([
    0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    0x05, 0x00
  ]);

  const bitStringLength = pkcs1Bytes.length + 1;
  const totalContentLength = algorithmIdentifier.length + 1 + lengthBytes(bitStringLength).length + bitStringLength;

  const result = new Uint8Array(1 + lengthBytes(totalContentLength).length + totalContentLength);
  let offset = 0;

  result[offset++] = 0x30;
  const totalLengthBytes = lengthBytes(totalContentLength);
  result.set(totalLengthBytes, offset);
  offset += totalLengthBytes.length;

  result.set(algorithmIdentifier, offset);
  offset += algorithmIdentifier.length;

  result[offset++] = 0x03;
  const bitStringLengthBytes = lengthBytes(bitStringLength);
  result.set(bitStringLengthBytes, offset);
  offset += bitStringLengthBytes.length;
  result[offset++] = 0x00;
  result.set(pkcs1Bytes, offset);

  return result;
}

// Encodes a length value in DER (Distinguished Encoding Rules) format.
// DER length encoding rules:
// - Lengths 0-127: single byte containing the length
// - Lengths 128-255: 0x81 followed by one byte containing the length
// - Lengths 256-65535: 0x82 followed by two bytes containing the length (big-endian)
// Used by pkcs1ToSpki() to construct valid ASN.1/DER structures.
function lengthBytes(length: number): Uint8Array {
  if (length < 128) {
    return new Uint8Array([length]);
  } else if (length < 256) {
    return new Uint8Array([0x81, length]);
  } else {
    return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
  }
}

// Imports cryptographic public keys into the Web Crypto API format (CryptoKey).
// This function is specific to the browser implementation and doesn't exist in sigstore-js.
//
// Why needed for browser:
// - sigstore-js uses Node.js crypto.createPublicKey() which handles many key formats automatically
// - Browsers only have Web Crypto API (crypto.subtle.importKey) which requires explicit format/algorithm
// - This function bridges the gap by:
//   1. Detecting key format (PEM, hex, base64, PKCS#1, SPKI)
//   2. Converting PKCS#1 RSA keys to SPKI (Web Crypto only supports SPKI for RSA)
//   3. Mapping Sigstore key types/schemes to Web Crypto algorithm parameters
//
// Supports:
// - ECDSA (P-256, P-384, P-521) - Used by Fulcio, CT logs
// - Ed25519 - Used by Rekor checkpoints, some CT logs
// - RSA (PKCS#1, PSS) - Used by older CT logs and some Rekor instances
//
// Key format detection:
// - PEM format (contains "BEGIN"): Parse with toDER()
// - Hex string (all hex chars): Import as raw
// - Base64 PKCS#1 (starts with 0x30 0x82...): Convert to SPKI
// - Base64 SPKI: Import directly
export async function importKey(
  keytype: string,
  scheme: string,
  key: string,
): Promise<CryptoKey> {
  class importParams {
    format: "raw" | "spki" = "spki";
    keyData: ArrayBuffer = new ArrayBuffer(0);
    algorithm: RsaHashedImportParams | EcKeyImportParams | Algorithm = { name: "ECDSA" };
    extractable: boolean = true;
    usage: Array<KeyUsage> = ["verify"];
  }

  const params = new importParams();
  if (key.includes("BEGIN")) {
    params.format = "spki";
    params.keyData = toArrayBuffer(toDER(key));
  } else if (/^[0-9A-Fa-f]+$/.test(key)) {
    params.format = "raw";
    params.keyData = toArrayBuffer(hexToUint8Array(key));
  } else {
    params.format = "spki";
    const keyBytes = base64ToUint8Array(key);

    if (keytype.toLowerCase().includes("pkcs1") &&
        keyBytes[0] === 0x30 && keyBytes[1] === 0x82 &&
        keyBytes[4] === 0x02 && keyBytes[5] === 0x82) {
      params.keyData = toArrayBuffer(pkcs1ToSpki(keyBytes));
    } else {
      params.keyData = toArrayBuffer(keyBytes);
    }
  }

  if (keytype.toLowerCase().includes("ecdsa")) {
    if (scheme.includes("256")) {
      params.algorithm = { name: "ECDSA", namedCurve: EcdsaTypes.P256 };
    } else if (scheme.includes("384")) {
      params.algorithm = { name: "ECDSA", namedCurve: EcdsaTypes.P384 };
    } else if (scheme.includes("521")) {
      params.algorithm = { name: "ECDSA", namedCurve: EcdsaTypes.P521 };
    } else {
      throw new Error("Cannot determine ECDSA key size.");
    }
  } else if (keytype.toLowerCase().includes("ed25519")) {
    params.algorithm = { name: "Ed25519" };
  } else if (keytype.toLowerCase().includes("rsa") || keytype.toLowerCase().includes("pkcs1")) {
    let hashName = HashAlgorithms.SHA256;
    // Normalize scheme to handle various formats: SHA256, SHA_256, SHA-256, etc.
    const normalizedScheme = scheme.toUpperCase().replace(/[-_]/g, "");
    if (normalizedScheme.includes("SHA256") || normalizedScheme.includes("256")) {
      hashName = HashAlgorithms.SHA256;
    } else if (normalizedScheme.includes("SHA384") || normalizedScheme.includes("384")) {
      hashName = HashAlgorithms.SHA384;
    } else if (normalizedScheme.includes("SHA512") || normalizedScheme.includes("512")) {
      hashName = HashAlgorithms.SHA512;
    }

    if (scheme.includes("PKCS1") || scheme.includes("RSA_PKCS1")) {
      params.algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: hashName },
      };
    } else {
      params.algorithm = {
        name: "RSA-PSS",
        hash: { name: hashName },
      };
    }
  } else {
    throw new Error(`Unsupported ${keytype}`);
  }

  return await crypto.subtle.importKey(
    params.format,
    params.keyData,
    params.algorithm,
    params.extractable,
    params.usage,
  );
}

export async function verifySignature(
  key: CryptoKey,
  signed: Uint8Array,
  sig: Uint8Array,
  hash: string = "sha256",
): Promise<boolean> {
  const options: {
    name: string;
    hash?: {
      name: string;
    };
  } = {
    name: key.algorithm.name,
  };

  if (key.algorithm.name === KeyTypes.Ecdsa) {
    const namedCurve = (key.algorithm as EcKeyAlgorithm).namedCurve;
    let sig_size = 32;

    if (namedCurve === EcdsaTypes.P256) {
      sig_size = 32;
    } else if (namedCurve === EcdsaTypes.P384) {
      sig_size = 48;
    } else if (namedCurve === EcdsaTypes.P521) {
      sig_size = 66;
    }

    options.hash = { name: "" };
    if (hash.includes("256")) {
      options.hash.name = HashAlgorithms.SHA256;
    } else if (hash.includes("384")) {
      options.hash.name = HashAlgorithms.SHA384;
    } else if (hash.includes("512")) {
      options.hash.name = HashAlgorithms.SHA512;
    } else {
      throw new Error("Cannot determine hashing algorithm;");
    }

    let raw_signature: Uint8Array;
    try {
      const asn1_sig = ASN1Obj.parseBuffer(sig);
      const r = asn1_sig.subs[0].toInteger();
      const s = asn1_sig.subs[1].toInteger();
      const binr = hexToUint8Array(r.toString(16).padStart(sig_size * 2, "0"));
      const bins = hexToUint8Array(s.toString(16).padStart(sig_size * 2, "0"));
      raw_signature = new Uint8Array(binr.length + bins.length);
      raw_signature.set(binr, 0);
      raw_signature.set(bins, binr.length);
    } catch {
      return false;
    }

    return await crypto.subtle.verify(
      options,
      key,
      toArrayBuffer(raw_signature),
      toArrayBuffer(signed),
    );
  } else if (key.algorithm.name === KeyTypes.Ed25519) {
    // Ed25519 uses raw signatures (not DER-encoded like ECDSA)
    // Fulcio supports Ed25519, ECDSA, and RSA_PSS for signing certificates
    // Ed25519 is also used for checkpoint signatures in TLog configurations
    return await crypto.subtle.verify(
      key.algorithm.name,
      key,
      toArrayBuffer(sig),
      toArrayBuffer(signed),
    );
  } else if (key.algorithm.name === "RSA-PSS") {
    // Salt length must match the hash output size
    const hashAlg = (key.algorithm as RsaHashedKeyAlgorithm).hash.name;
    const saltLength = hashAlg === HashAlgorithms.SHA256 ? 32 :
                       hashAlg === HashAlgorithms.SHA384 ? 48 :
                       hashAlg === HashAlgorithms.SHA512 ? 64 : 32;
    return await crypto.subtle.verify(
      {
        name: "RSA-PSS",
        saltLength: saltLength,
      },
      key,
      toArrayBuffer(sig),
      toArrayBuffer(signed),
    );
  } else if (key.algorithm.name === "RSASSA-PKCS1-v1_5") {
    return await crypto.subtle.verify(
      key.algorithm.name,
      key,
      toArrayBuffer(sig),
      toArrayBuffer(signed),
    );
  } else {
    throw new Error("Unsupported key type!");
  }
}

// Verifies an ECDSA signature over a pre-computed digest.
// WebCrypto's verify() always hashes the input first, so passing a digest would
// result in double-hashing. We use @noble/curves for low-level ECDSA verification,
// adapted from the same workaround used in sigstore-js's conformance CLI.
// See: https://github.com/sigstore/sigstore-js/blob/main/packages/conformance/src/commands/verify-bundle.ts#L111
export async function verifySignatureOverDigest(
  key: CryptoKey,
  digest: Uint8Array,
  sig: Uint8Array,
): Promise<boolean> {
  if (key.algorithm.name !== KeyTypes.Ecdsa) {
    throw new Error("verifySignatureOverDigest only supports ECDSA keys");
  }

  const namedCurve = (key.algorithm as EcKeyAlgorithm).namedCurve;
  let curve: typeof p256 | typeof p384 | typeof p521;

  if (namedCurve === EcdsaTypes.P256) {
    curve = p256;
  } else if (namedCurve === EcdsaTypes.P384) {
    curve = p384;
  } else if (namedCurve === EcdsaTypes.P521) {
    curve = p521;
  } else {
    throw new Error(`Unsupported curve: ${namedCurve}`);
  }

  // Export the public key to get x and y coordinates
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (!jwk.x || !jwk.y) {
    throw new Error("Invalid ECDSA public key: missing x or y coordinates");
  }

  // Convert base64url JWK coordinates to bytes
  const x = base64UrlToUint8Array(jwk.x);
  const y = base64UrlToUint8Array(jwk.y);

  // Combine x and y into uncompressed public key format (0x04 || x || y)
  const publicKey = new Uint8Array(1 + x.length + y.length);
  publicKey[0] = 0x04;
  publicKey.set(x, 1);
  publicKey.set(y, 1 + x.length);

  // Verify the DER-encoded signature over the digest
  // @noble/curves can parse DER signatures directly with format: 'der'
  // Options:
  // - format: 'der' to parse DER-encoded signatures
  // - prehash: false because we're passing a pre-computed digest, not the original message
  // - lowS: false to accept both high-S and low-S signatures (matches elliptic.js behavior)
  //   elliptic.js accepts malleable signatures by default, while @noble/curves rejects them by default
  return curve.verify(sig, digest, publicKey, { format: 'der', prehash: false, lowS: false });
}

export { uint8ArrayEqual as bufferEqual } from "./encoding.js";
