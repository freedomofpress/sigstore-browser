export { SigstoreVerifier } from "./sigstore.js";
export type { SigstoreVerifierOptions } from "./sigstore.js";
export type { SigstoreBundle, TLogEntry, VerificationMaterial, MessageSignature, TimestampVerificationData, RFC3161Timestamp } from "./bundle.js";
export type { TrustedRoot, Sigstore, RawTimestampAuthority } from "./interfaces.js";
export {
  VerificationError,
  TimestampError,
  CertificateError,
  TLogError,
  SignatureError,
  PolicyError,
} from "./errors.js";
export { verifyRFC3161Timestamp, verifyBundleTimestamp } from "./timestamp/tsa.js";
export { TrustedRootProvider, type TrustedRootProviderOptions } from "./trust/tuf.js";
