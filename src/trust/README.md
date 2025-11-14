# Trust Material

This directory contains trust material for Sigstore verification.

## tuf-root.json

**Source**: Extracted from [sigstore-js/packages/tuf/seeds.json](https://github.com/sigstore/sigstore-js/blob/main/packages/tuf/seeds.json)

**Purpose**: Bootstrap TUF (The Update Framework) client with a pinned root of trust for the Sigstore TUF repository.

**Content**: Base64-encoded TUF `root.json` metadata for `https://tuf-repo-cdn.sigstore.dev`
- Type: TUF root metadata (version 13)
- Expires: 2026-01-22
- Contains: 5 root signing keys with threshold signature requirement

**Security**: This file prevents MITM attacks during TUF initialization by embedding the initial root metadata instead of fetching it from the network. The TUF client uses this to verify all subsequent TUF metadata updates.

**Updates**: Should be updated when sigstore-js updates its embedded TUF root. Check the sigstore-js repository for the latest version.

## Relationship to default-trusted-root.json

- **tuf-root.json**: Root of trust for TUF itself (verifies TUF metadata)
- **default-trusted-root.json**: Sigstore trust material (CAs, CT logs, TLogs, TSAs) delivered via TUF

These are two distinct files serving different purposes in the trust chain.
