/*
Copyright 2023 The Sigstore Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import { ASN1Obj, bufferEqual, verifySignature } from "@freedomofpress/crypto-browser";
import { HashAlgorithms } from "../interfaces.js";
import { ECDSA_SIGNATURE_ALGOS, RSA_SIGNATURE_ALGOS, SHA2_HASH_ALGOS } from "../oid.js";
import { RFC3161TimestampVerificationError } from "./error.js";
import { TSTInfo } from "./tstinfo.js";

const OID_PKCS9_CONTENT_TYPE_SIGNED_DATA = "1.2.840.113549.1.7.2";
const OID_PKCS9_CONTENT_TYPE_TSTINFO = "1.2.840.113549.1.9.16.1.4";
const OID_PKCS9_MESSAGE_DIGEST_KEY = "1.2.840.113549.1.9.4";

export class RFC3161Timestamp {
  public root: ASN1Obj;

  constructor(asn1: ASN1Obj) {
    this.root = asn1;
  }

  public static parse(der: Uint8Array): RFC3161Timestamp {
    const asn1 = ASN1Obj.parseBuffer(der);
    return new RFC3161Timestamp(asn1);
  }

  get status(): bigint {
    return this.pkiStatusInfoObj.subs[0].toInteger();
  }

  get contentType(): string {
    return this.contentTypeObj.toOID();
  }

  get eContentType(): string {
    return this.eContentTypeObj.toOID();
  }

  get signingTime(): Date {
    return this.tstInfo.genTime;
  }

  get signerIssuer(): Uint8Array {
    return this.signerSidObj.subs[0].value;
  }

  get signerSerialNumber(): Uint8Array {
    return this.signerSidObj.subs[1].value;
  }

  get signerDigestAlgorithm(): string {
    const oid = this.signerDigestAlgorithmObj.subs[0].toOID();
    const algo = SHA2_HASH_ALGOS[oid];
    if (!algo) {
      throw new Error(`Unknown digest algorithm OID: ${oid}`);
    }
    return algo;
  }

  get signatureAlgorithm(): string {
    const oid = this.signatureAlgorithmObj.subs[0].toOID();
    const algo = ECDSA_SIGNATURE_ALGOS[oid] || RSA_SIGNATURE_ALGOS[oid];
    return algo;
  }

  get signatureValue(): Uint8Array {
    return this.signatureValueObj.value;
  }

  get tstInfo(): TSTInfo {
    // Need to unpack tstInfo from an OCTET STRING
    return new TSTInfo(this.eContentObj.subs[0].subs[0]);
  }

  public async verify(data: Uint8Array, publicKey: CryptoKey): Promise<void> {
    if (!this.timeStampTokenObj) {
      throw new RFC3161TimestampVerificationError("timeStampToken is missing");
    }

    // Check for expected ContentInfo content type
    if (this.contentType !== OID_PKCS9_CONTENT_TYPE_SIGNED_DATA) {
      throw new RFC3161TimestampVerificationError(
        `incorrect content type: ${this.contentType}`,
      );
    }

    // Check for expected encapsulated content type
    if (this.eContentType !== OID_PKCS9_CONTENT_TYPE_TSTINFO) {
      throw new RFC3161TimestampVerificationError(
        `incorrect encapsulated content type: ${this.eContentType}`,
      );
    }

    // Check that the tstInfo references the correct artifact
    await this.tstInfo.verify(data);
    // Check that the signed message digest matches the tstInfo
    await this.verifyMessageDigest();
    // Check that the signature is valid for the signed attributes
    await this.verifySignature(publicKey);
  }

  private async verifyMessageDigest(): Promise<void> {
    // Check that the tstInfo matches the signed data
    const hashAlg = this.signerDigestAlgorithm;

    // Convert hash algorithm name to the format expected by WebCrypto
    const hashAlgName = hashAlg === "sha256" ? HashAlgorithms.SHA256 :
                       hashAlg === "sha384" ? HashAlgorithms.SHA384 :
                       hashAlg === "sha512" ? HashAlgorithms.SHA512 : hashAlg;

    const tstInfoDigest = await crypto.subtle.digest(
      hashAlgName,
      this.tstInfo.raw as Uint8Array<ArrayBuffer>,
    );
    const expectedDigest = this.messageDigestAttributeObj.subs[1].subs[0].value;

    if (!bufferEqual(new Uint8Array(tstInfoDigest), expectedDigest)) {
      throw new RFC3161TimestampVerificationError(
        "signed data does not match tstInfo",
      );
    }
  }

  private async verifySignature(key: CryptoKey): Promise<void> {
    // Encode the signed attributes for verification
    const signedAttrs = this.signedAttrsObj.toDER();
    signedAttrs[0] = 0x31; // Change context-specific tag to SET

    const oid = this.signatureAlgorithmObj.subs[0].toOID();
    // Try both ECDSA and RSA signature algorithms
    const algo = ECDSA_SIGNATURE_ALGOS[oid] || RSA_SIGNATURE_ALGOS[oid];

    if (!algo) {
      throw new RFC3161TimestampVerificationError(
        `Unsupported signature algorithm OID: ${oid}`,
      );
    }

    // Check that the signature is valid for the signed attributes
    const verified = await verifySignature(
      key,
      signedAttrs,
      this.signatureValue,
      algo,
    );

    if (!verified) {
      throw new RFC3161TimestampVerificationError(
        "signature verification failed",
      );
    }
  }

  // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
  private get pkiStatusInfoObj(): ASN1Obj {
    // pkiStatusInfo is the first element of the timestamp response sequence
    return this.root.subs[0];
  }

  // https://www.rfc-editor.org/rfc/rfc3161#section-2.4.2
  private get timeStampTokenObj(): ASN1Obj {
    // timeStampToken is the first element of the timestamp response sequence
    return this.root.subs[1];
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-3
  private get contentTypeObj(): ASN1Obj {
    return this.timeStampTokenObj.subs[0];
  }
  // https://www.rfc-editor.org/rfc/rfc5652#section-3
  private get signedDataObj(): ASN1Obj {
    const obj = this.timeStampTokenObj.subs.find((sub) =>
      sub.tag.isContextSpecific(0x00),
    );
    if (!obj) {
      throw new RFC3161TimestampVerificationError(
        "Missing timeStampTokenObj sub.",
      );
    }
    return obj.subs[0];
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.1
  private get encapContentInfoObj(): ASN1Obj {
    return this.signedDataObj.subs[2];
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.1
  private get signerInfosObj(): ASN1Obj {
    // SignerInfos is the last element of the signed data sequence
    const sd = this.signedDataObj;
    return sd.subs[sd.subs.length - 1];
  }

  // https://www.rfc-editor.org/rfc/rfc5652#section-5.1
  private get signerInfoObj(): ASN1Obj {
    // Only supporting one signer
    return this.signerInfosObj.subs[0];
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.2
  private get eContentTypeObj(): ASN1Obj {
    return this.encapContentInfoObj.subs[0];
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.2
  private get eContentObj(): ASN1Obj {
    return this.encapContentInfoObj.subs[1];
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
  private get signedAttrsObj(): ASN1Obj {
    const signedAttrs = this.signerInfoObj.subs.find((sub) =>
      sub.tag.isContextSpecific(0x00),
    );
    if (!signedAttrs) {
      throw new RFC3161TimestampVerificationError("Missing signedAttrsObj.");
    }
    return signedAttrs;
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
  private get messageDigestAttributeObj(): ASN1Obj {
    const messageDigest = this.signedAttrsObj.subs.find(
      (sub) =>
        sub.subs[0].tag.isOID() &&
        sub.subs[0].toOID() === OID_PKCS9_MESSAGE_DIGEST_KEY,
    );
    if (!messageDigest) {
      throw new RFC3161TimestampVerificationError("Missing messageDigest.");
    }
    return messageDigest;
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
  private get signerSidObj(): ASN1Obj {
    return this.signerInfoObj.subs[1];
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
  private get signerDigestAlgorithmObj(): ASN1Obj {
    // Signature is the 2nd element of the signerInfoObj object
    return this.signerInfoObj.subs[2];
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
  private get signatureAlgorithmObj(): ASN1Obj {
    // Signature is the 4th element of the signerInfoObj object
    return this.signerInfoObj.subs[4];
  }

  // https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
  private get signatureValueObj(): ASN1Obj {
    // Signature is the 6th element of the signerInfoObj object
    return this.signerInfoObj.subs[5];
  }
}
