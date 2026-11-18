# Minimal Browser-Compatible Implementation of a Sigstore Verifier

[![Conformance](https://github.com/freedomofpress/sigstore-browser/actions/workflows/conformance.yml/badge.svg)](https://github.com/freedomofpress/sigstore-browser/actions/workflows/conformance.yml)

A minimal TypeScript implementation of [Sigstore](https://sigstore.dev/) verification, optimized for browser compatibility.

This is a browser-compatible alternative to [sigstore-js](https://github.com/sigstore/sigstore-js) that focuses on verification functionality needed for secure software updates in browser environments.

> [!CAUTION]
> This library has not received an independent security audit. Maintenance is performed by volunteers, and the project is not officially supported or endorsed by the Freedom of the Press Foundation.

## Features

- **Full Sigstore Verification**: Complete verification of Sigstore bundles including certificate chains, transparency logs, and timestamps
- **Browser-First**: Designed for web browsers using the Web Crypto API
- **TUF Integration**: Secure trusted root updates via [The Update Framework](https://theupdateframework.io/)
- **Policy Verification**: Flexible identity and claim verification adapted from sigstore-python
- **Multiple Bundle Formats**: Supports Sigstore bundle versions 0.2 and 0.3 by default, and 0.1 when enabled
- **Multiple Key Types**: RSA, ECDSA, and Ed25519 signature verification via Web Crypto API
- **Minimal Dependencies**: Only depends on [@freedomofpress/crypto-browser](https://github.com/freedomofpress/crypto-browser), [@freedomofpress/tuf-browser](https://github.com/freedomofpress/tuf-browser), and [@noble/curves](https://github.com/paulmillr/noble-curves)

## Installation

```bash
npm install @freedomofpress/sigstore-browser
```

## Usage

### Basic Verification

```typescript
import { SigstoreVerifier } from '@freedomofpress/sigstore-browser';

// Initialize the verifier
const verifier = new SigstoreVerifier();

// Load the Sigstore trusted root via TUF (recommended)
await verifier.loadSigstoreRootWithTUF();

// Or load a trusted root directly
// await verifier.loadSigstoreRoot(trustedRootJson);

// Verify an artifact
const bundle = JSON.parse(bundleJsonString);
const artifactData = new Uint8Array(/* artifact bytes */);

const verified = await verifier.verifyArtifact(
  'identity@example.com',           // Expected signer identity (SAN)
  'https://accounts.google.com',    // Expected OIDC issuer
  bundle,
  artifactData,
  false
);
```

### Verification Options

```typescript
const verifier = new SigstoreVerifier({
  tlogThreshold: 1,   // Minimum distinct log operators with a fully verified entry (default: 1)
  ctlogThreshold: 1,  // Minimum distinct CT log operators with a verified SCT (default: 1)
  tsaThreshold: 0,    // Minimum distinct TSA operators with a verified timestamp (default: 0)
  bundleVersions: ["0.2", "0.3"], // Accepted bundle versions; add "0.1" for legacy bundles that carry only an inclusion promise (default: ["0.2", "0.3"])
});
```

Thresholds must be non-negative safe integers. Authorities without `operator` metadata can satisfy a threshold of one, but never add to the count of named operators. Thresholds above one require that many distinct, explicitly named operators.

When `isDigestOnly` is `true`, supply exactly 32 bytes containing the artifact's SHA-256 digest and construct the verifier with `verifyDigest: verifySignatureOverDigest` from `@freedomofpress/crypto-browser/noble`. Verifiers that always have the artifact can leave it out, and their bundles do not carry `@noble/curves`.

## What Gets Verified

The `verifyArtifact` method performs the following checks:

1. **Bundle Validation**: Structure, a 16 MiB aggregate encoded-data limit, bounded certificate chains and a supported media type
2. **Identity Verification**: Certificate SAN matches the expected identity
3. **Issuer Verification**: Certificate OIDC issuer matches the expected issuer
4. **Transparency Log**: Every entry from a trusted Rekor log is verified (inclusion promise, Merkle proof, checkpoint, body and logged certificate); the threshold counts distinct log operators
5. **TSA Timestamp Verification**: RFC 3161 timestamps (if present); the threshold counts distinct operators
6. **Observer Timestamps**: At least one verified integrated time or TSA timestamp must anchor the signature
7. **Certificate Chain**: Leaf certificate chains to a Fulcio CA that was trusted at every observer timestamp
8. **SCT Verification**: Signed Certificate Timestamps from CT logs; the threshold counts distinct operators
9. **Signature Verification**: Artifact signature using the certificate's public key

Use `verifyArtifactPolicy(policy, bundle, artifactData, isDigestOnly)` to enforce a custom `VerificationPolicy`, including the required identity and issuer checks.
Policies may be synchronous or asynchronous; asynchronous policies are awaited before verification continues.

## Managed-Key Bundles

`ManagedKeyVerifier` verifies bundles signed with a key you already trust instead of a Fulcio
certificate, for example a KMS key used through `cosign attest-blob --key` or `cosign sign-blob --key`. It handles ECDSA
P-256 and P-384 keys, including P-384 signature bundles that Cosign logs in Rekor v2 as
`hashedrekord` 0.0.2 entries (SHA-384 of the DSSE pre-authentication encoding, or of the artifact for a blob signature).

```typescript
import { ManagedKeyVerifier, STRICT_MANAGED_KEY_PROFILE, VerificationError } from '@freedomofpress/sigstore-browser';

const verifier = new ManagedKeyVerifier(STRICT_MANAGED_KEY_PROFILE); // or new ManagedKeyVerifier() for the defaults
await verifier.loadTrustedRoot(trustedRootJson); // or await verifier.loadTrustedRootWithTUF();

try {
  // bundleJson: the bundle as text (or UTF-8 bytes); publicKeyPem: the key you trust (PEM or DER SPKI)
  const { payloadType, payload, timestamps } = await verifier.verifyDsse(bundleJson, publicKeyPem);
  // Check the statement in `payload` (subject, predicate) yourself.
} catch (e) {
  if (e instanceof VerificationError) console.error(e.code, e.message); // e.g. "tlog-key-mismatch"
  throw e;
}
```

`verifyArtifact(bundle, publicKey, data, isDigestOnly)` checks a `messageSignature`, or an in-toto
subject, against the artifact or its digest. The digest is the one the content implies: SHA-256 for
an in-toto subject, or the digest the key implies for a `messageSignature` (SHA-256 for P-256,
SHA-384 for P-384). It accepts either content type whatever the options; to require a DSSE envelope,
call `verifyDsse`.

The key you pass is the only key used. A bundle's `publicKey.hint` never selects or installs a
key, there is no certificate or identity fallback, and a bundle carrying a certificate is
rejected. A bundle or key that fails verification raises a `VerificationError` whose `code` is one
of `REASON_CODES`. Misuse raises ordinary errors instead: invalid constructor options, verifying
before a trusted root is loaded, a digest of the wrong length for the content and key, a digest-only
`messageSignature` without `verifyDigest`.

By default the checks match the certificate flow: bundle v0.2 and v0.3; every entry from a trusted
log fully verified (inclusion proof, checkpoint signed by that entry's log key with witness
cosignatures ignored, entry body bound to the key, signature and digest; inclusion promise if
present); every RFC 3161 timestamp verified against the trusted root's authorities, never against
certificates embedded in the token; at least one verified observer time. For a Rekor v2 entry the
logged key details, digest algorithm and digest length must agree with the key.

Loading the trusted root is per key: a log key or timestamp authority that this runtime cannot
load (an unsupported or malformed key or validity period, Ed25519 without native support or the
fallback) only affects entries that need it. Fulcio CAs and CT logs are not used.

Stricter options. None applies by default; `STRICT_MANAGED_KEY_PROFILE` enables each switch and
sets each list to the value shown:

| Option | Effect |
| --- | --- |
| `bundleVersions: ["0.3"]` | Only bundle v0.3 |
| `requireCanonicalMediaType` | Only the canonical spelling `application/vnd.dev.sigstore.bundle.vX.Y+json`, not the legacy `application/vnd.dev.sigstore.bundle+json;version=X.Y` (with the line above: exactly `application/vnd.dev.sigstore.bundle.v0.3+json`) |
| `requireSingleTlogEntry` | Exactly one transparency log entry; an extra one fails, with or without a proof |
| `allowedEntryKinds: ["hashedrekord/0.0.2"]` | Only Rekor v2 hashedrekord entries |
| `rejectIntegratedTime`, `rejectInclusionPromise` | No Rekor v1 metadata on the entry, whatever its value |
| `requireSingleTimestamp` | Exactly one RFC 3161 timestamp |
| `checkpointOriginBinding` | Checkpoint origin and log signature line name must be the host of the entry's log `baseUrl`; entries naming an unknown log fail |

Repeated JSON member names follow `JSON.parse` semantics: the last value wins, including under
`STRICT_MANAGED_KEY_PROFILE`. Callers that prohibit repeated names must check the JSON before
calling the verifier. Conflicting protobuf content or verification-material variants are still rejected.

`maxBundleBytes` (default 16 MiB) bounds bundles passed as text or bytes before they are parsed.
On runtimes without WebCrypto Ed25519 (Safari before 17), call `installEd25519Fallback()` from
`@freedomofpress/crypto-browser/noble` first, as for the certificate flow.

`test/vectors/managed-key` holds real Cosign P-384 and P-256 bundles and single-mutation negatives,
shared with sigstore-rust, with the expected outcome and reason code of each.

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run tests (browser environment via Playwright)
npm test

# The same tests in Chromium, Firefox and WebKit, and in Node
npm run test:browsers
npm run test:node

# The managed-key corpus on the built library in Node
# (also: bun test/runtime-matrix.ts); the second run uses the Ed25519 fallback
npm run test:runtime

# Lint and format
npm run lint
```

## Related Projects

This library is part of a family of browser-compatible security libraries:

- [@freedomofpress/tuf-browser](https://github.com/freedomofpress/tuf-browser) - Browser-compatible TUF client
- [@freedomofpress/crypto-browser](https://github.com/freedomofpress/crypto-browser) - Browser-compatible cryptographic primitives

## License

Apache License 2.0 - see [LICENSE](LICENSE) file for details. Portions of this package incorporate code from [sigstore-js](https://github.com/sigstore/sigstore-js) and [sigstore-python](https://github.com/sigstore/sigstore-python).

## Acknowledgments

This project is based on the [Sigstore specification](https://docs.sigstore.dev/) and adapted from:
- [sigstore-js](https://github.com/sigstore/sigstore-js)
- [sigstore-go](https://github.com/sigstore/sigstore-go)
- [sigstore-python](https://github.com/sigstore/sigstore-python)
