# Vendored test vectors

| Directory | Contents |
| --- | --- |
| `managed-key/` | Managed-key DSSE and blob / Rekor v2 / RFC 3161 corpus: real Cosign v3.1.4 bundles and single-mutation negatives, with `manifest.json` (expected outcome and reason code per vector), `PROFILE.md` (the strict profile) and the generator |

`test/corpus/data.ts` loads the corpus. `test/corpus/check.ts` runs them against the library in
`src/managed.corpus.browser.test.ts` (browsers and Node) and `test/runtime-matrix.ts` (the built
`dist/` on Node and Bun); `src/managed*.browser.test.ts` also take fixtures from `managed-key/`.

## The managed-key corpus

`managed-key/` is copied byte for byte from `test-vectors/managed-key` in
<https://github.com/MaplePrivacyLabs/sigstore-rust>, a sigstore-rust fork that holds the original,
at commit `47e17243e38f6aaa472008c2187b43e143b14211`. Paths in `managed-key/README.md` that name
Rust files refer to that repository, and "this library" there means sigstore-rust. Do not edit the
directory here. To compare it with its source and check that it regenerates (Python 3 and the
OpenSSL 3.2+ command line):

```sh
git clone https://github.com/MaplePrivacyLabs/sigstore-rust
git -C sigstore-rust checkout 47e17243e38f6aaa472008c2187b43e143b14211
diff -r sigstore-rust/test-vectors/managed-key test/vectors/managed-key
python3 test/vectors/managed-key/generate.py --check
```

Each vector in `manifest.json` records three expectations:

- `profile` is the shared contract: the outcome and reason code under the strict profile of
  `PROFILE.md`. Browser exceptions under `STRICT_MANAGED_KEY_PROFILE` are listed in
  `STRICT_MODE_DIFFERENCES` in `test/corpus/check.ts`.
- `library` and `library_checkpoint_log_binding` are sigstore-rust's behavior with its default
  options, without and with its checkpoint binding option. They are not requirements for this
  library.

With `ManagedKeyVerifier`'s default options this library follows its own certificate flow, so
twelve vectors differ from sigstore-rust's `library` expectation. `DEFAULT_MODE_DIFFERENCES` in
`test/corpus/check.ts` lists each one with its expected outcome here and the reason.

The browser verifier uses `JSON.parse` and does not reject repeated JSON member names, even
under the strict preset. The shared duplicate-envelope vector still expects the profile's
`duplicate-json-key`; the browser instead rejects the last envelope's signature as
`dsse-signature-invalid`. Callers that require the shared profile's duplicate-member rule must
enforce it before calling the verifier. The shared corpus is not modified for this exception.
