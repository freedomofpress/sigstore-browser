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

/*
 * Certificate chain verification for browser environments
 *
 * Ported from sigstore-js:
 * https://github.com/sigstore/sigstore-js/blob/main/packages/verify/src/key/certificate.ts
 *
 * Key differences from sigstore-js:
 * - Browser-compatible: async verify() method for Web Crypto API
 * - Uses Uint8Array instead of Buffer for binary data
 * - Uses bufferEqual for Uint8Array comparisons
 */

import { X509Certificate } from "./cert.js";
import { bufferEqual } from "../crypto.js";

interface CertificateChainVerifierOptions {
  trustedCerts: X509Certificate[];
  untrustedCert: X509Certificate;
  timestamp: Date;
}

export class CertificateChainVerifier {
  private untrustedCert: X509Certificate;
  private trustedCerts: X509Certificate[];
  private localCerts: X509Certificate[];
  private timestamp: Date;

  constructor(opts: CertificateChainVerifierOptions) {
    this.untrustedCert = opts.untrustedCert;
    this.trustedCerts = opts.trustedCerts;
    this.localCerts = dedupeCertificates([
      ...opts.trustedCerts,
      opts.untrustedCert,
    ]);
    this.timestamp = opts.timestamp;
  }

  public async verify(): Promise<X509Certificate[]> {
    const certificatePath = await this.sort();

    this.checkPath(certificatePath);

    const validForDate = certificatePath.every((cert) =>
      cert.validForDate(this.timestamp)
    );

    if (!validForDate) {
      throw new Error(
        "certificate is not valid or expired at the specified date"
      );
    }

    return certificatePath;
  }

  private async sort(): Promise<X509Certificate[]> {
    const leafCert = this.untrustedCert;

    let paths = await this.buildPaths(leafCert);

    paths = paths.filter((path) =>
      path.some((cert) => this.trustedCerts.includes(cert))
    );

    if (paths.length === 0) {
      throw new Error("no trusted certificate path found");
    }

    const path = paths.reduce((prev, curr) =>
      prev.length < curr.length ? prev : curr
    );

    return [leafCert, ...path].slice(0, -1);
  }

  private async buildPaths(
    certificate: X509Certificate
  ): Promise<X509Certificate[][]> {
    const paths = [];
    const issuers = await this.findIssuer(certificate);

    if (issuers.length === 0) {
      throw new Error("no valid certificate path found");
    }

    for (let i = 0; i < issuers.length; i++) {
      const issuer = issuers[i];

      if (issuer.equals(certificate)) {
        paths.push([certificate]);
        continue;
      }

      const subPaths = await this.buildPaths(issuer);

      for (let j = 0; j < subPaths.length; j++) {
        paths.push([issuer, ...subPaths[j]]);
      }
    }

    return paths;
  }

  private async findIssuer(
    certificate: X509Certificate
  ): Promise<X509Certificate[]> {
    let issuers: X509Certificate[] = [];
    let keyIdentifier: Uint8Array | undefined;

    if (bufferEqual(certificate.subject, certificate.issuer)) {
      if (await certificate.verify()) {
        return [certificate];
      }
    }

    if (certificate.extAuthorityKeyID) {
      keyIdentifier = certificate.extAuthorityKeyID.keyIdentifier;
    }

    this.localCerts.forEach((possibleIssuer) => {
      if (keyIdentifier) {
        if (possibleIssuer.extSubjectKeyID) {
          if (
            bufferEqual(
              possibleIssuer.extSubjectKeyID.keyIdentifier,
              keyIdentifier
            )
          ) {
            issuers.push(possibleIssuer);
          }
          return;
        }
      }

      if (bufferEqual(possibleIssuer.subject, certificate.issuer)) {
        issuers.push(possibleIssuer);
      }
    });

    const verifiedIssuers: X509Certificate[] = [];
    for (const issuer of issuers) {
      try {
        if (await certificate.verify(issuer)) {
          verifiedIssuers.push(issuer);
        }
      } catch (ex) {
        // Ignore verification failures
      }
    }

    return verifiedIssuers;
  }

  private checkPath(path: X509Certificate[]): void {
    if (path.length < 1) {
      throw new Error(
        "certificate chain must contain at least one certificate"
      );
    }

    const validCAs = path.slice(1).every((cert) => cert.isCA);
    if (!validCAs) {
      throw new Error("intermediate certificate is not a CA");
    }

    for (let i = path.length - 2; i >= 0; i--) {
      if (!bufferEqual(path[i].issuer, path[i + 1].subject)) {
        throw new Error("incorrect certificate name chaining");
      }
    }

    for (let i = 0; i < path.length; i++) {
      const cert = path[i];

      if (cert.extBasicConstraints?.isCA) {
        const pathLength = cert.extBasicConstraints.pathLenConstraint;

        if (pathLength !== undefined && pathLength < BigInt(i - 1)) {
          throw new Error("path length constraint exceeded");
        }
      }
    }
  }
}

function dedupeCertificates(certs: X509Certificate[]): X509Certificate[] {
  for (let i = 0; i < certs.length; i++) {
    for (let j = i + 1; j < certs.length; j++) {
      if (certs[i].equals(certs[j])) {
        certs.splice(j, 1);
        j--;
      }
    }
  }
  return certs;
}
