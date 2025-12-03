/**
 * Adapted from sigstore-python sigstore/verify/policy.py
 *
 * This module provides policy verification for checking certificate identity claims.
 * Each policy class verifies a specific X.509 extension value against an expected value.
 *
 * There are two types of extension formats:
 * - V1 extensions: Raw OCTET STRING containing the value directly
 * - V2 extensions: DER-encoded UTF8String (RFC 5280 compliant)
 *
 * Policies can be combined using:
 * - AllOf: All child policies must pass (logical AND)
 * - AnyOf: At least one child policy must pass (logical OR)
 * - Identity: Verifies SAN with optional issuer check
 */

import { PolicyError } from "./errors.js";
import {
  X509Certificate,
  EXTENSION_OID_FULCIO_ISSUER_V1,
  EXTENSION_OID_GITHUB_WORKFLOW_TRIGGER,
  EXTENSION_OID_GITHUB_WORKFLOW_SHA,
  EXTENSION_OID_GITHUB_WORKFLOW_NAME,
  EXTENSION_OID_GITHUB_WORKFLOW_REPOSITORY,
  EXTENSION_OID_GITHUB_WORKFLOW_REF,
  EXTENSION_OID_OTHERNAME,
  EXTENSION_OID_FULCIO_ISSUER_V2,
  EXTENSION_OID_BUILD_SIGNER_URI,
  EXTENSION_OID_BUILD_SIGNER_DIGEST,
  EXTENSION_OID_RUNNER_ENVIRONMENT,
  EXTENSION_OID_SOURCE_REPOSITORY_URI,
  EXTENSION_OID_SOURCE_REPOSITORY_DIGEST,
  EXTENSION_OID_SOURCE_REPOSITORY_REF,
  EXTENSION_OID_SOURCE_REPOSITORY_IDENTIFIER,
  EXTENSION_OID_SOURCE_REPOSITORY_OWNER_URI,
  EXTENSION_OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER,
  EXTENSION_OID_BUILD_CONFIG_URI,
  EXTENSION_OID_BUILD_CONFIG_DIGEST,
  EXTENSION_OID_BUILD_TRIGGER,
  EXTENSION_OID_RUN_INVOCATION_URI,
  EXTENSION_OID_SOURCE_REPOSITORY_VISIBILITY,
} from "./x509/cert.js";

// Standard GitHub Actions OIDC issuer
// https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect
export const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";

/**
 * Interface that all verification policies conform to.
 */
export interface VerificationPolicy {
  verify(cert: X509Certificate): void;
}

/**
 * Base class for V1 extension policies (raw OCTET STRING value).
 */
abstract class SingleX509ExtPolicyV1 implements VerificationPolicy {
  abstract readonly oid: string;
  abstract readonly name: string;
  protected readonly expectedValue: string;

  constructor(value: string) {
    this.expectedValue = value;
  }

  protected abstract getExtensionValue(cert: X509Certificate): string | undefined;

  verify(cert: X509Certificate): void {
    const extValue = this.getExtensionValue(cert);
    if (extValue === undefined) {
      throw new PolicyError(
        `Certificate does not contain ${this.name} (${this.oid}) extension`
      );
    }
    if (extValue !== this.expectedValue) {
      throw new PolicyError(
        `Certificate's ${this.name} does not match ` +
        `(got '${extValue}', expected '${this.expectedValue}')`
      );
    }
  }
}

/**
 * Base class for V2 extension policies (DER-encoded UTF8String).
 * Uses the same verify logic as V1 since our extension classes handle the parsing.
 */
abstract class SingleX509ExtPolicyV2 extends SingleX509ExtPolicyV1 {}

// ============================================================================
// V1 Extension Policies (OID 1.3.6.1.4.1.57264.1.1 - 1.3.6.1.4.1.57264.1.6)
// ============================================================================

/**
 * Verifies the certificate's OIDC issuer (V1 format).
 * OID: 1.3.6.1.4.1.57264.1.1
 */
export class OIDCIssuer extends SingleX509ExtPolicyV1 {
  readonly oid = EXTENSION_OID_FULCIO_ISSUER_V1;
  readonly name = "OIDCIssuer";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extFulcioIssuerV1?.issuer;
  }
}

/**
 * Verifies the certificate's GitHub Actions workflow trigger.
 * OID: 1.3.6.1.4.1.57264.1.2
 */
export class GitHubWorkflowTrigger extends SingleX509ExtPolicyV1 {
  readonly oid = EXTENSION_OID_GITHUB_WORKFLOW_TRIGGER;
  readonly name = "GitHubWorkflowTrigger";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extGitHubWorkflowTrigger?.workflowTrigger;
  }
}

/**
 * Verifies the certificate's GitHub Actions workflow commit SHA.
 * OID: 1.3.6.1.4.1.57264.1.3
 */
export class GitHubWorkflowSHA extends SingleX509ExtPolicyV1 {
  readonly oid = EXTENSION_OID_GITHUB_WORKFLOW_SHA;
  readonly name = "GitHubWorkflowSHA";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extGitHubWorkflowSHA?.workflowSHA;
  }
}

/**
 * Verifies the certificate's GitHub Actions workflow name.
 * OID: 1.3.6.1.4.1.57264.1.4
 */
export class GitHubWorkflowName extends SingleX509ExtPolicyV1 {
  readonly oid = EXTENSION_OID_GITHUB_WORKFLOW_NAME;
  readonly name = "GitHubWorkflowName";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extGitHubWorkflowName?.workflowName;
  }
}

/**
 * Verifies the certificate's GitHub Actions workflow repository.
 * OID: 1.3.6.1.4.1.57264.1.5
 */
export class GitHubWorkflowRepository extends SingleX509ExtPolicyV1 {
  readonly oid = EXTENSION_OID_GITHUB_WORKFLOW_REPOSITORY;
  readonly name = "GitHubWorkflowRepository";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extGitHubWorkflowRepository?.workflowRepository;
  }
}

/**
 * Verifies the certificate's GitHub Actions workflow ref.
 * OID: 1.3.6.1.4.1.57264.1.6
 */
export class GitHubWorkflowRef extends SingleX509ExtPolicyV1 {
  readonly oid = EXTENSION_OID_GITHUB_WORKFLOW_REF;
  readonly name = "GitHubWorkflowRef";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extGitHubWorkflowRef?.workflowRef;
  }
}

// ============================================================================
// V2 Extension Policies (OID 1.3.6.1.4.1.57264.1.8 - 1.3.6.1.4.1.57264.1.22)
// ============================================================================

/**
 * Verifies the certificate's OIDC issuer (V2 format, DER-encoded).
 * OID: 1.3.6.1.4.1.57264.1.8
 */
export class OIDCIssuerV2 extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_FULCIO_ISSUER_V2;
  readonly name = "OIDCIssuerV2";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extFulcioIssuerV2?.issuer;
  }
}

/**
 * Verifies the certificate's Build Signer URI.
 * OID: 1.3.6.1.4.1.57264.1.9
 */
export class OIDCBuildSignerURI extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_BUILD_SIGNER_URI;
  readonly name = "OIDCBuildSignerURI";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extBuildSignerURI?.buildSignerURI;
  }
}

/**
 * Verifies the certificate's Build Signer Digest.
 * OID: 1.3.6.1.4.1.57264.1.10
 */
export class OIDCBuildSignerDigest extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_BUILD_SIGNER_DIGEST;
  readonly name = "OIDCBuildSignerDigest";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extBuildSignerDigest?.buildSignerDigest;
  }
}

/**
 * Verifies the certificate's Runner Environment.
 * OID: 1.3.6.1.4.1.57264.1.11
 */
export class OIDCRunnerEnvironment extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_RUNNER_ENVIRONMENT;
  readonly name = "OIDCRunnerEnvironment";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extRunnerEnvironment?.runnerEnvironment;
  }
}

/**
 * Verifies the certificate's Source Repository URI.
 * OID: 1.3.6.1.4.1.57264.1.12
 */
export class OIDCSourceRepositoryURI extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_SOURCE_REPOSITORY_URI;
  readonly name = "OIDCSourceRepositoryURI";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extSourceRepositoryURI?.sourceRepositoryURI;
  }
}

/**
 * Verifies the certificate's Source Repository Digest.
 * OID: 1.3.6.1.4.1.57264.1.13
 */
export class OIDCSourceRepositoryDigest extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_SOURCE_REPOSITORY_DIGEST;
  readonly name = "OIDCSourceRepositoryDigest";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extSourceRepositoryDigest?.sourceRepositoryDigest;
  }
}

/**
 * Verifies the certificate's Source Repository Ref.
 * OID: 1.3.6.1.4.1.57264.1.14
 */
export class OIDCSourceRepositoryRef extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_SOURCE_REPOSITORY_REF;
  readonly name = "OIDCSourceRepositoryRef";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extSourceRepositoryRef?.sourceRepositoryRef;
  }
}

/**
 * Verifies the certificate's Source Repository Identifier.
 * OID: 1.3.6.1.4.1.57264.1.15
 */
export class OIDCSourceRepositoryIdentifier extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_SOURCE_REPOSITORY_IDENTIFIER;
  readonly name = "OIDCSourceRepositoryIdentifier";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extSourceRepositoryIdentifier?.sourceRepositoryIdentifier;
  }
}

/**
 * Verifies the certificate's Source Repository Owner URI.
 * OID: 1.3.6.1.4.1.57264.1.16
 */
export class OIDCSourceRepositoryOwnerURI extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_SOURCE_REPOSITORY_OWNER_URI;
  readonly name = "OIDCSourceRepositoryOwnerURI";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extSourceRepositoryOwnerURI?.sourceRepositoryOwnerURI;
  }
}

/**
 * Verifies the certificate's Source Repository Owner Identifier.
 * OID: 1.3.6.1.4.1.57264.1.17
 */
export class OIDCSourceRepositoryOwnerIdentifier extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_SOURCE_REPOSITORY_OWNER_IDENTIFIER;
  readonly name = "OIDCSourceRepositoryOwnerIdentifier";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extSourceRepositoryOwnerIdentifier?.sourceRepositoryOwnerIdentifier;
  }
}

/**
 * Verifies the certificate's Build Config URI.
 * OID: 1.3.6.1.4.1.57264.1.18
 */
export class OIDCBuildConfigURI extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_BUILD_CONFIG_URI;
  readonly name = "OIDCBuildConfigURI";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extBuildConfigURI?.buildConfigURI;
  }
}

/**
 * Verifies the certificate's Build Config Digest.
 * OID: 1.3.6.1.4.1.57264.1.19
 */
export class OIDCBuildConfigDigest extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_BUILD_CONFIG_DIGEST;
  readonly name = "OIDCBuildConfigDigest";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extBuildConfigDigest?.buildConfigDigest;
  }
}

/**
 * Verifies the certificate's Build Trigger.
 * OID: 1.3.6.1.4.1.57264.1.20
 */
export class OIDCBuildTrigger extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_BUILD_TRIGGER;
  readonly name = "OIDCBuildTrigger";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extBuildTrigger?.buildTrigger;
  }
}

/**
 * Verifies the certificate's Run Invocation URI.
 * OID: 1.3.6.1.4.1.57264.1.21
 */
export class OIDCRunInvocationURI extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_RUN_INVOCATION_URI;
  readonly name = "OIDCRunInvocationURI";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extRunInvocationURI?.runInvocationURI;
  }
}

/**
 * Verifies the certificate's Source Repository Visibility at signing.
 * OID: 1.3.6.1.4.1.57264.1.22
 */
export class OIDCSourceRepositoryVisibility extends SingleX509ExtPolicyV2 {
  readonly oid = EXTENSION_OID_SOURCE_REPOSITORY_VISIBILITY;
  readonly name = "OIDCSourceRepositoryVisibility";

  protected getExtensionValue(cert: X509Certificate): string | undefined {
    return cert.extSourceRepositoryVisibility?.sourceRepositoryVisibility;
  }
}

// ============================================================================
// Policy Combinators
// ============================================================================

/**
 * The "any of" policy, corresponding to a logical OR between child policies.
 * An empty list of child policies is considered trivially invalid.
 */
export class AnyOf implements VerificationPolicy {
  private children: VerificationPolicy[];

  constructor(children: VerificationPolicy[]) {
    this.children = children;
  }

  verify(cert: X509Certificate): void {
    for (const child of this.children) {
      try {
        child.verify(cert);
        return;
      } catch {
        // Continue to next policy
      }
    }
    throw new PolicyError(`0 of ${this.children.length} policies succeeded`);
  }
}

/**
 * The "all of" policy, corresponding to a logical AND between child policies.
 * An empty list of child policies is considered trivially invalid.
 */
export class AllOf implements VerificationPolicy {
  private children: VerificationPolicy[];

  constructor(children: VerificationPolicy[]) {
    this.children = children;
  }

  verify(cert: X509Certificate): void {
    if (this.children.length < 1) {
      throw new PolicyError("no child policies to verify");
    }
    for (const child of this.children) {
      child.verify(cert);
    }
  }
}

// ============================================================================
// Identity Policy
// ============================================================================

/**
 * Verifies the certificate's "identity", corresponding to the X.509v3 SAN.
 *
 * Identities can be verified modulo an OIDC issuer, to prevent an unexpected
 * issuer from offering a particular identity.
 *
 * Supported SAN types include emails, URIs, and Sigstore-specific "other names".
 */
export class Identity implements VerificationPolicy {
  private identity: string;
  private issuerPolicy: OIDCIssuer | null;

  constructor(options: { identity: string; issuer?: string }) {
    this.identity = options.identity;
    this.issuerPolicy = options.issuer ? new OIDCIssuer(options.issuer) : null;
  }

  verify(cert: X509Certificate): void {
    if (this.issuerPolicy) {
      this.issuerPolicy.verify(cert);
    }

    const sanExt = cert.extSubjectAltName;
    if (!sanExt) {
      throw new PolicyError("Certificate does not contain SubjectAlternativeName extension");
    }

    const allSans = new Set<string>();

    // Add email (rfc822Name)
    if (sanExt.rfc822Name) {
      allSans.add(sanExt.rfc822Name);
    }

    // Add URI
    if (sanExt.uri) {
      allSans.add(sanExt.uri);
    }

    // Add Sigstore-specific otherName
    const otherName = sanExt.otherName(EXTENSION_OID_OTHERNAME);
    if (otherName) {
      allSans.add(otherName);
    }

    if (!allSans.has(this.identity)) {
      throw new PolicyError(
        `Certificate's SANs do not match ${this.identity}; actual SANs: ${Array.from(allSans).join(", ")}`
      );
    }
  }
}
