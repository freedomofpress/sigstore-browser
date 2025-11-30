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
import {
  ASN1Obj,
  importKey,
  toDER,
  Uint8ArrayToBase64,
  uint8ArrayEqual,
  verifySignature,
} from "@freedomofpress/crypto-browser";
import { KeyTypes } from "../interfaces.js";
import { DEFAULT_HASH_ALGORITHM, ECDSA_CURVE_NAMES, ECDSA_SIGNATURE_ALGOS, OID_RSASSA_PSS, RSA_SIGNATURE_ALGOS, SHA2_HASH_ALGOS } from "../oid.js";
import {
  X509AuthorityKeyIDExtension,
  X509BasicConstraintsExtension,
  X509Extension,
  X509FulcioIssuerV1,
  X509FulcioIssuerV2,
  X509KeyUsageExtension,
  X509SCTExtension,
  X509SubjectAlternativeNameExtension,
  X509SubjectKeyIDExtension,
} from "./ext.js";

// https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
const EXTENSION_OID_SUBJECT_KEY_ID = "2.5.29.14";
const EXTENSION_OID_KEY_USAGE = "2.5.29.15";
const EXTENSION_OID_SUBJECT_ALT_NAME = "2.5.29.17";
const EXTENSION_OID_BASIC_CONSTRAINTS = "2.5.29.19";
const EXTENSION_OID_AUTHORITY_KEY_ID = "2.5.29.35";
const EXTENSION_OID_FULCIO_ISSUER_V1 = "1.3.6.1.4.1.57264.1.1";
const EXTENSION_OID_FULCIO_ISSUER_V2 = "1.3.6.1.4.1.57264.1.8";

export const EXTENSION_OID_SCT = "1.3.6.1.4.1.11129.2.4.2";

export class X509Certificate {
  public root: ASN1Obj;

  constructor(asn1: ASN1Obj) {
    this.root = asn1;
  }

  public static parse(cert: Uint8Array | string): X509Certificate {
    const der = typeof cert === "string" ? toDER(cert) : cert;
    const asn1 = ASN1Obj.parseBuffer(der);
    return new X509Certificate(asn1);
  }

  get tbsCertificate(): ASN1Obj {
    return this.tbsCertificateObj;
  }

  get version(): string {
    // version number is the first element of the version context specific tag
    const ver = this.versionObj.subs[0].toInteger();
    return `v${(ver + BigInt(1)).toString()}`;
  }

  get serialNumber(): Uint8Array {
    return this.serialNumberObj.value;
  }

  get notBefore(): Date {
    // notBefore is the first element of the validity sequence
    return this.validityObj.subs[0].toDate();
  }

  get notAfter(): Date {
    // notAfter is the second element of the validity sequence
    return this.validityObj.subs[1].toDate();
  }

  get issuer(): Uint8Array {
    return this.issuerObj.value;
  }

  get subject(): Uint8Array {
    return this.subjectObj.value;
  }

  get publicKey(): Uint8Array {
    return this.subjectPublicKeyInfoObj.toDER();
  }

  /**
   * Import the public key with a specific hash algorithm and signature scheme for RSA keys.
   * For ECDSA keys, both parameters are ignored.
   * @param hashAlg - Hash algorithm (e.g., "sha384") for RSA keys
   * @param usePss - If true, import as RSA-PSS key; if false, import as PKCS#1 v1.5
   */
  public async getPublicKeyObj(hashAlg?: string, usePss?: boolean): Promise<CryptoKey> {
    const publicKey = this.subjectPublicKeyInfoObj.toDER();
    const spki = ASN1Obj.parseBuffer(publicKey);
    const algorithmOID = spki.subs[0].subs[0].toOID();

    // RSA key (OID 1.2.840.113549.1.1.1) or RSA-PSS key (OID 1.2.840.113549.1.1.10)
    const isRsaKey = algorithmOID === "1.2.840.113549.1.1.1";
    const isRsaPssKey = algorithmOID === OID_RSASSA_PSS;

    if (isRsaPssKey) {
      // WebCrypto doesn't support importing keys with id-RSASSA-PSS OID, only rsaEncryption
      throw new Error(
        "RSA-PSS public keys (id-RSASSA-PSS OID) are not supported by WebCrypto. " +
        "Only certificates with standard RSA keys (rsaEncryption OID) signed using RSA-PSS are supported."
      );
    }

    if (isRsaKey) {
      const hash = hashAlg || DEFAULT_HASH_ALGORITHM;
      // crypto-browser extracts hash from scheme and uses PSS unless "PKCS1" is present
      const scheme = usePss ? hash : `PKCS1_${hash}`;
      return importKey(KeyTypes.RSA, scheme, Uint8ArrayToBase64(publicKey));
    } else {
      // ECDSA key - the curve OID is in the second element
      const curveOID = spki.subs[0].subs[1]?.toOID();
      const curve = ECDSA_CURVE_NAMES[curveOID];
      if (!curve) {
        throw new Error(`Unknown ECDSA curve OID: ${curveOID}`);
      }
      return importKey(KeyTypes.Ecdsa, curve, Uint8ArrayToBase64(publicKey));
    }
  }

  get publicKeyObj(): Promise<CryptoKey> {
    return this.getPublicKeyObj();
  }

  get signatureAlgorithm(): string {
    const oid: string = this.signatureAlgorithmObj.subs[0].toOID();
    return ECDSA_SIGNATURE_ALGOS[oid] || RSA_SIGNATURE_ALGOS[oid] || this.parseRsaPssHashAlgorithm();
  }

  get signatureAlgorithmOid(): string {
    return this.signatureAlgorithmObj.subs[0].toOID();
  }

  /**
   * Parse hash algorithm from RSA-PSS signature algorithm parameters.
   * RSA-PSS parameters are: SEQUENCE { hashAlgorithm, maskGenAlgorithm, saltLength, trailerField }
   */
  private parseRsaPssHashAlgorithm(): string {
    const sigAlgOid = this.signatureAlgorithmObj.subs[0].toOID();
    if (sigAlgOid !== OID_RSASSA_PSS) {
      return "";
    }

    // RSA-PSS has parameters in the second element of the signature algorithm sequence
    const params = this.signatureAlgorithmObj.subs[1];
    if (!params || params.subs.length === 0) {
      return DEFAULT_HASH_ALGORITHM;
    }

    // First element is hashAlgorithm [0] EXPLICIT
    const hashAlgWrapper = params.subs[0];
    if (hashAlgWrapper && hashAlgWrapper.subs.length > 0) {
      // The wrapper contains a SEQUENCE with the hash algorithm OID
      const hashAlgSeq = hashAlgWrapper.subs[0];
      if (hashAlgSeq && hashAlgSeq.subs.length > 0) {
        const hashOid = hashAlgSeq.subs[0].toOID();
        return SHA2_HASH_ALGOS[hashOid] || DEFAULT_HASH_ALGORITHM;
      }
    }

    return DEFAULT_HASH_ALGORITHM;
  }

  get signatureValue(): Uint8Array {
    // Signature value is a bit string, so we need to skip the first byte
    return this.signatureValueObj.value.subarray(1);
  }

  get subjectAltName(): string | undefined {
    const ext = this.extSubjectAltName;
    return ext?.uri || ext?.rfc822Name;
  }

  get extensions(): ASN1Obj[] {
    // The extension list is the first (and only) element of the extensions
    // context specific tag
    const extSeq = this.extensionsObj?.subs[0];
    return extSeq?.subs || /* istanbul ignore next */ [];
  }

  get extKeyUsage(): X509KeyUsageExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_KEY_USAGE);
    return ext ? new X509KeyUsageExtension(ext) : undefined;
  }

  get extBasicConstraints(): X509BasicConstraintsExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_BASIC_CONSTRAINTS);
    return ext ? new X509BasicConstraintsExtension(ext) : undefined;
  }

  get extSubjectAltName(): X509SubjectAlternativeNameExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_SUBJECT_ALT_NAME);
    return ext ? new X509SubjectAlternativeNameExtension(ext) : undefined;
  }

  get extAuthorityKeyID(): X509AuthorityKeyIDExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_AUTHORITY_KEY_ID);
    return ext ? new X509AuthorityKeyIDExtension(ext) : undefined;
  }

  get extSubjectKeyID(): X509SubjectKeyIDExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_SUBJECT_KEY_ID);
    return ext
      ? new X509SubjectKeyIDExtension(ext)
      : /* istanbul ignore next */ undefined;
  }

  get extSCT(): X509SCTExtension | undefined {
    const ext = this.findExtension(EXTENSION_OID_SCT);
    return ext ? new X509SCTExtension(ext) : undefined;
  }

  get extFulcioIssuerV1(): X509FulcioIssuerV1 | undefined {
    const ext = this.findExtension(EXTENSION_OID_FULCIO_ISSUER_V1);
    return ext ? new X509FulcioIssuerV1(ext) : undefined;
  }

  get extFulcioIssuerV2(): X509FulcioIssuerV2 | undefined {
    const ext = this.findExtension(EXTENSION_OID_FULCIO_ISSUER_V2);
    return ext ? new X509FulcioIssuerV2(ext) : undefined;
  }

  get isCA(): boolean {
    const ca = this.extBasicConstraints?.isCA || false;

    // If the KeyUsage extension is present, keyCertSign must be set
    if (this.extKeyUsage) {
      return ca && this.extKeyUsage.keyCertSign;
    }

    return ca;
  }

  public extension(oid: string): X509Extension | undefined {
    const ext = this.findExtension(oid);
    return ext ? new X509Extension(ext) : undefined;
  }

  public async verify(issuerCertificate?: X509Certificate): Promise<boolean> {
    // Extract the hash algorithm from this certificate's signature algorithm
    const sigAlgOID = this.signatureAlgorithmOid;
    const isRsaPss = sigAlgOID === OID_RSASSA_PSS;

    // Get hash algorithm - for RSA-PSS, parse from parameters; otherwise lookup in tables
    const hashAlg = isRsaPss
      ? this.parseRsaPssHashAlgorithm()
      : (RSA_SIGNATURE_ALGOS[sigAlgOID] || ECDSA_SIGNATURE_ALGOS[sigAlgOID]);

    // Use the issuer's public key if provided, otherwise use the subject's (for self-signed certs)
    // Import with the correct hash algorithm and key type for this certificate's signature
    const publicKeyObj = issuerCertificate
      ? await issuerCertificate.getPublicKeyObj(hashAlg, isRsaPss)
      : await this.getPublicKeyObj(hashAlg, isRsaPss);

    return await verifySignature(
      publicKeyObj,
      this.tbsCertificate.toDER(),
      this.signatureValue,
      this.signatureAlgorithm,
    );
  }

  public validForDate(date: Date): boolean {
    return this.notBefore <= date && date <= this.notAfter;
  }

  public equals(other: X509Certificate): boolean {
    return uint8ArrayEqual(this.root.toDER(), other.root.toDER());
  }

  // Creates a copy of the certificate with a new buffer
  public clone(): X509Certificate {
    const der = this.root.toDER();
    const clone = new Uint8Array(der);
    return X509Certificate.parse(clone);
  }

  private findExtension(oid: string): ASN1Obj | undefined {
    // Find the extension with the given OID. The OID will always be the first
    // element of the extension sequence
    return this.extensions.find((ext) => ext.subs[0].toOID() === oid);
  }

  /////////////////////////////////////////////////////////////////////////////
  // The following properties use the documented x509 structure to locate the
  // desired ASN.1 object
  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.1
  private get tbsCertificateObj(): ASN1Obj {
    // tbsCertificate is the first element of the certificate sequence
    return this.root.subs[0];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.2
  private get signatureAlgorithmObj(): ASN1Obj {
    // signatureAlgorithm is the second element of the certificate sequence
    return this.root.subs[1];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.1.3
  private get signatureValueObj(): ASN1Obj {
    // signatureValue is the third element of the certificate sequence
    return this.root.subs[2];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.1
  private get versionObj(): ASN1Obj {
    // version is the first element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[0];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.2
  private get serialNumberObj(): ASN1Obj {
    // serialNumber is the second element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[1];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.4
  private get issuerObj(): ASN1Obj {
    // issuer is the fourth element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[3];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5
  private get validityObj(): ASN1Obj {
    // version is the fifth element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[4];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.6
  private get subjectObj(): ASN1Obj {
    // subject is the sixth element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[5];
  }

  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.7
  private get subjectPublicKeyInfoObj(): ASN1Obj {
    // subjectPublicKeyInfo is the seventh element of the tbsCertificate sequence
    return this.tbsCertificateObj.subs[6];
  }

  // Extensions can't be located by index because their position varies. Instead,
  // we need to find the extensions context specific tag
  // https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.9
  private get extensionsObj(): ASN1Obj | undefined {
    return this.tbsCertificateObj.subs.find((sub) =>
      sub.tag.isContextSpecific(0x03),
    );
  }
}
