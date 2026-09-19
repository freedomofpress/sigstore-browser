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
- **Multiple Bundle Formats**: Supports Sigstore bundle versions 0.1, 0.2, and 0.3
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
});
```

Thresholds must be non-negative safe integers. Authorities without `operator` metadata can satisfy a threshold of one, but never add to the count of named operators. Thresholds above one require that many distinct, explicitly named operators.

When `isDigestOnly` is `true`, supply exactly 32 bytes containing the artifact's SHA-256 digest.

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

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build

# Run tests (browser environment via Playwright)
npm test

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
