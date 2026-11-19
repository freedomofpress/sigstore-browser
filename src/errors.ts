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

/**
 * Base class for all verification errors
 * Provides structured error handling with error codes
 */
export class VerificationError extends Error {
  constructor(public code: string, message: string) {
    super(message);
    this.name = 'VerificationError';
    Object.setPrototypeOf(this, VerificationError.prototype);
  }
}

/**
 * Error thrown when timestamp verification fails
 */
export class TimestampError extends VerificationError {
  constructor(message: string) {
    super('TIMESTAMP_ERROR', message);
    this.name = 'TimestampError';
    Object.setPrototypeOf(this, TimestampError.prototype);
  }
}

/**
 * Error thrown when certificate verification fails
 */
export class CertificateError extends VerificationError {
  constructor(message: string) {
    super('CERTIFICATE_ERROR', message);
    this.name = 'CertificateError';
    Object.setPrototypeOf(this, CertificateError.prototype);
  }
}

/**
 * Error thrown when transparency log verification fails
 */
export class TLogError extends VerificationError {
  constructor(message: string) {
    super('TLOG_ERROR', message);
    this.name = 'TLogError';
    Object.setPrototypeOf(this, TLogError.prototype);
  }
}

/**
 * Error thrown when signature verification fails
 */
export class SignatureError extends VerificationError {
  constructor(message: string) {
    super('SIGNATURE_ERROR', message);
    this.name = 'SignatureError';
    Object.setPrototypeOf(this, SignatureError.prototype);
  }
}

/**
 * Error thrown when policy verification fails
 */
export class PolicyError extends VerificationError {
  constructor(message: string) {
    super('POLICY_ERROR', message);
    this.name = 'PolicyError';
    Object.setPrototypeOf(this, PolicyError.prototype);
  }
}

/**
 * Language-neutral reasons a managed-key verification fails, carried in
 * VerificationError.code. They name the first check that failed. The shared
 * managed-key test corpus records the same codes for its vectors.
 */
export const REASON_CODES = [
  // Bundle input and structure
  "bundle-too-large",
  "bundle-malformed",
  "conflicting-oneof",
  "media-type-unsupported",
  "verification-material-unsupported",
  "content-unsupported",
  // Transparency log entries
  "tlog-entry-count",
  "tlog-entry-kind",
  "tlog-entry-malformed",
  "tlog-unknown-log",
  "tlog-log-key-unsupported",
  "tlog-threshold",
  "integrated-time-present",
  "inclusion-promise-present",
  "inclusion-promise-missing",
  "inclusion-promise-invalid",
  "inclusion-proof-missing",
  "inclusion-proof-invalid",
  "checkpoint-malformed",
  "checkpoint-origin-mismatch",
  "checkpoint-signature-invalid",
  "tlog-key-details-mismatch",
  "tlog-digest-algorithm-mismatch",
  "tlog-digest-malformed",
  "tlog-digest-mismatch",
  "tlog-key-mismatch",
  "tlog-signature-mismatch",
  // Signed content
  "key-unsupported",
  "dsse-signature-invalid",
  "message-signature-invalid",
  "payload-type-unsupported",
  "artifact-mismatch",
  // RFC 3161 timestamps
  "timestamp-count",
  "timestamp-duplicate",
  "timestamp-malformed",
  "timestamp-untrusted-authority",
  "timestamp-message-mismatch",
  "timestamp-signature-invalid",
  "timestamp-threshold",
] as const;

export type ReasonCode = (typeof REASON_CODES)[number];

/** Throws a VerificationError whose code is one of REASON_CODES. */
export function fail(code: ReasonCode, message: string): never {
  throw new VerificationError(code, message);
}

/** The message carried by an error, including values thrown without an Error wrapper. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
