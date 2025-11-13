import { ASN1Obj } from "./asn1/index.js";
import {
  base64ToUint8Array,
  hexToUint8Array,
  toArrayBuffer,
} from "./encoding.js";
import { EcdsaTypes, HashAlgorithms, KeyTypes } from "./interfaces.js";
import { toDER } from "./pem.js";

export async function importKey(
  keytype: string,
  scheme: string,
  key: string,
): Promise<CryptoKey> {
  class importParams {
    format: "raw" | "spki" = "spki";
    keyData: ArrayBuffer = new ArrayBuffer(0);
    algorithm: {
      name: "ECDSA" | "Ed25519" | "RSASSA-PKCS1-v1_5" | "RSA-PSS" | "RSA-OAEP";
      namedCurve?: EcdsaTypes;
    } = { name: "ECDSA" };
    extractable: boolean = true;
    usage: Array<KeyUsage> = ["verify"];
  }

  const params = new importParams();
  // Let's try to detect the encoding
  if (key.includes("BEGIN")) {
    // If it has a begin then it is a PEM
    params.format = "spki";
    params.keyData = toArrayBuffer(toDER(key));
  } else if (/^[0-9A-Fa-f]+$/.test(key)) {
    // Is it hex?
    params.format = "raw";
    params.keyData = toArrayBuffer(hexToUint8Array(key));
  } else {
    // It might be base64, without the PEM header, as in sigstore trusted_root
    params.format = "spki";
    params.keyData = toArrayBuffer(base64ToUint8Array(key));
  }

  // Let's see supported key types
  if (keytype.toLowerCase().includes("ecdsa")) {
    // Let'd find out the key size, and retrieve the proper naming for crypto.subtle
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
    // Ed2559 eys can be only one size, we do not need more info
    params.algorithm = { name: "Ed25519" };
  } else if (keytype.toLowerCase().includes("rsa")) {
    // Is it even worth to think of supporting it?
    throw new Error("TODO (or maybe not): impleent RSA keys support.");
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
    // Later we need to supply exactly sized R and R dependingont he curve for sig verification
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
    // Then we need to select an hashing algorithm
    if (hash.includes("256")) {
      options.hash.name = HashAlgorithms.SHA256;
    } else if (hash.includes("384")) {
      options.hash.name = HashAlgorithms.SHA384;
    } else if (hash.includes("512")) {
      options.hash.name = HashAlgorithms.SHA512;
    } else {
      throw new Error("Cannot determine hashing algorithm;");
    }

    // For posterity: this mess is because the web crypto API supports only
    // IEEE P1363, so we etract r and s from the DER sig and manually ancode
    // big endian and append them one after each other

    // The verify option will do hashing internally
    // const signed_digest = await crypto.subtle.digest(hash_alg, signed)
    let raw_signature: Uint8Array;
    try {
      const asn1_sig = ASN1Obj.parseBuffer(sig);
      const r = asn1_sig.subs[0].toInteger();
      const s = asn1_sig.subs[1].toInteger();
      // Sometimes the integers can be less than the average, and we would miss bytes. The functione expects a finxed
      // input in bytes depending on the curve, or it fails early.
      const binr = hexToUint8Array(r.toString(16).padStart(sig_size * 2, "0"));
      const bins = hexToUint8Array(s.toString(16).padStart(sig_size * 2, "0"));
      raw_signature = new Uint8Array(binr.length + bins.length);
      raw_signature.set(binr, 0);
      raw_signature.set(bins, binr.length);
    } catch {
      // Signature is probably malformed
      return false;
    }

    return await crypto.subtle.verify(
      options,
      key,
      toArrayBuffer(raw_signature),
      toArrayBuffer(signed),
    );
  } else if (key.algorithm.name === KeyTypes.Ed25519) {
    return await crypto.subtle.verify(
      key.algorithm.name,
      key,
      toArrayBuffer(sig),
      toArrayBuffer(signed),
    );
  } else if (key.algorithm.name === KeyTypes.RSA) {
    throw new Error("RSA could work, if only someone coded the support :)");
  } else {
    throw new Error("Unsupported key type!");
  }
}

export function bufferEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
