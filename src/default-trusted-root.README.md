# Default Trusted Root

This file contains a static snapshot of the Sigstore public good trusted root.

**Source**: Retrieved via `gh attestation trusted-root` on 2025-11-12

**Future**: This static file will be replaced with dynamic TUF-based fetching once `tuf-mini-ts` is published to npm and can be reliably used as a dependency. The TUF client will fetch and verify the latest trusted root from https://tuf-repo-cdn.sigstore.dev.

**Note**: This file should be periodically updated until TUF integration is complete.
