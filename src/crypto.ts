import { ASN1Obj } from "./asn1/index.js";
import {
  base64ToUint8Array,
  hexToUint8Array,
  toArrayBuffer,
  Uint8ArrayToHex,
} from "./encoding.js";
import { EcdsaTypes, HashAlgorithms, KeyTypes } from "./interfaces.js";
import { toDER } from "./pem.js";
import pkg from "elliptic";
const { ec: EC } = pkg;

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

function lengthBytes(length: number): Uint8Array {
  if (length < 128) {
    return new Uint8Array([length]);
  } else if (length < 256) {
    return new Uint8Array([0x81, length]);
  } else {
    return new Uint8Array([0x82, (length >> 8) & 0xff, length & 0xff]);
  }
}

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
    if (scheme.includes("PKCS1") || scheme.includes("RSA_PKCS1")) {
      params.algorithm = {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      };
    } else {
      params.algorithm = {
        name: "RSA-PSS",
        hash: { name: "SHA-256" },
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

    if (namedCurve === "P-256") {
      sig_size = 32;
    } else if (namedCurve === "P-384") {
      sig_size = 48;
    } else if (namedCurve === "P-521") {
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
    throw new Error(
      "This is untested but could likely work, but not for prod usage :)",
    );
  } else if (key.algorithm.name === "RSA-PSS") {
    const saltLength = 32;
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

export async function verifySignatureOverDigest(
  key: CryptoKey,
  digest: Uint8Array,
  sig: Uint8Array,
): Promise<boolean> {
  if (key.algorithm.name !== KeyTypes.Ecdsa) {
    throw new Error("verifySignatureOverDigest only supports ECDSA keys");
  }

  const namedCurve = (key.algorithm as EcKeyAlgorithm).namedCurve;
  let curveName: string;
  let sig_size: number;

  if (namedCurve === "P-256") {
    curveName = "p256";
    sig_size = 32;
  } else if (namedCurve === "P-384") {
    curveName = "p384";
    sig_size = 48;
  } else if (namedCurve === "P-521") {
    curveName = "p521";
    sig_size = 66;
  } else {
    throw new Error(`Unsupported curve: ${namedCurve}`);
  }

  const ec = new EC(curveName);

  // Parse the DER-encoded signature to extract r and s
  let r: bigint;
  let s: bigint;
  try {
    const asn1_sig = ASN1Obj.parseBuffer(sig);
    r = asn1_sig.subs[0].toInteger();
    s = asn1_sig.subs[1].toInteger();
  } catch {
    return false;
  }

  // Export the public key to get x and y coordinates
  const jwk = await crypto.subtle.exportKey("jwk", key);
  if (!jwk.x || !jwk.y) {
    throw new Error("Invalid ECDSA public key: missing x or y coordinates");
  }

  // Convert base64url JWK coordinates to hex
  const x = Buffer.from(jwk.x, "base64").toString("hex");
  const y = Buffer.from(jwk.y, "base64").toString("hex");

  // Create elliptic key from public key coordinates
  const eckey = ec.keyFromPublic({ x, y }, "hex");

  // Convert digest to hex string for elliptic
  const digestHex = Uint8ArrayToHex(digest);

  // Verify the signature over the digest
  const signature = {
    r: r.toString(16).padStart(sig_size * 2, "0"),
    s: s.toString(16).padStart(sig_size * 2, "0"),
  };

  return eckey.verify(digestHex, signature);
}

export { uint8ArrayEqual as bufferEqual } from "./encoding.js";
