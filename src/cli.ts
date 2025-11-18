#!/usr/bin/env node
import { createHash, webcrypto } from "node:crypto";
import { access, readFile } from "node:fs/promises";
import path from "node:path";

import { SigstoreBundle } from "./bundle.js";
import { base64ToUint8Array, hexToUint8Array, Uint8ArrayToHex, Uint8ArrayToString } from "./encoding.js";
import { TrustedRoot } from "./interfaces.js";
import { SigstoreVerifier } from "./sigstore.js";
import { TrustedRootProvider } from "./trust/tuf.js";

// Ensure the global Web Crypto implementation is available when running under Node.js
if (typeof globalThis.crypto === "undefined") {
  globalThis.crypto = webcrypto as unknown as Crypto;
}

interface CLIOptions {
  bundlePath: string;
  certificateIdentity: string;
  certificateOidcIssuer: string;
  trustedRootPath: string | undefined;
  artifactInput: string;
}

type ArtifactInput =
  | { type: "file"; path: string; data: Uint8Array; digestHex: string }
  | { type: "digest"; digestHex: string };

const USAGE = `Usage: sigstore-browser verify-bundle [--staging] --bundle FILE --certificate-identity IDENTITY --certificate-oidc-issuer URL [--trusted-root FILE] FILE_OR_DIGEST`;

function printUsage(): void {
  console.error(USAGE);
}

function parseArgs(argv: string[]): CLIOptions {
  const options: Partial<CLIOptions> = {};
  let command: string | undefined;
  let artifactInput: string | undefined;

  for (let i = 0; i < argv.length; i++) {
    const current = argv[i];

    if (current === "--help" || current === "-h") {
      printUsage();
      process.exit(0);
    }

    if (current.startsWith("--")) {
      const [name, providedValue] = current.split("=", 2);

      switch (name) {
        case "--bundle": {
          const value = providedValue ?? argv[++i];
          if (!value) {
            throw new Error("Missing value for --bundle");
          }
          options.bundlePath = value;
          break;
        }
        case "--certificate-identity": {
          const value = providedValue ?? argv[++i];
          if (!value) {
            throw new Error("Missing value for --certificate-identity");
          }
          options.certificateIdentity = value;
          break;
        }
        case "--certificate-oidc-issuer": {
          const value = providedValue ?? argv[++i];
          if (!value) {
            throw new Error("Missing value for --certificate-oidc-issuer");
          }
          options.certificateOidcIssuer = value;
          break;
        }
        case "--trusted-root": {
          const value = providedValue ?? argv[++i];
          if (!value) {
            throw new Error("Missing value for --trusted-root");
          }
          options.trustedRootPath = value;
          break;
        }
        default:
          throw new Error(`Unknown option: ${name}`);
      }

      continue;
    }

    if (!command) {
      command = current;
      continue;
    }

    if (!artifactInput) {
      artifactInput = current;
      continue;
    }

    throw new Error(`Unexpected argument: ${current}`);
  }

  if (command !== "verify-bundle") {
    throw new Error("No command provided. Expected 'verify-bundle'.");
  }

  if (!artifactInput) {
    throw new Error("Missing FILE_OR_DIGEST argument.");
  }

  if (!options.bundlePath) {
    throw new Error("Missing required option --bundle");
  }

  if (!options.certificateIdentity) {
    throw new Error("Missing required option --certificate-identity");
  }

  if (!options.certificateOidcIssuer) {
    throw new Error("Missing required option --certificate-oidc-issuer");
  }

  return {
    bundlePath: options.bundlePath,
    certificateIdentity: options.certificateIdentity,
    certificateOidcIssuer: options.certificateOidcIssuer,
    trustedRootPath: options.trustedRootPath,
    artifactInput,
  };
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function resolveArtifact(input: string): Promise<ArtifactInput> {
  const digestPrefix = "sha256:";

  if (
    input.startsWith(digestPrefix) &&
    input.length === digestPrefix.length + 64 &&
    /^[0-9a-fA-F]+$/.test(input.slice(digestPrefix.length)) &&
    !(await fileExists(input))
  ) {
    return {
      type: "digest",
      digestHex: input.slice(digestPrefix.length).toLowerCase(),
    };
  }

  const resolvedPath = path.resolve(input);
  const artifactBuffer = await readFile(resolvedPath);
  const digestHex = createHash("sha256").update(artifactBuffer).digest("hex");

  return {
    type: "file",
    path: resolvedPath,
    data: new Uint8Array(artifactBuffer),
    digestHex,
  };
}

async function loadTrustedRoot(
  pathInput: string | undefined,
): Promise<TrustedRoot> {
  if (!pathInput) {
    // Use TUF to fetch the latest trusted root (matches sigstore-js behavior)
    const tufProvider = new TrustedRootProvider({
      metadataUrl: "https://tuf-repo-cdn.sigstore.dev/",
      targetBaseUrl: "https://tuf-repo-cdn.sigstore.dev/targets/",
    });
    return await tufProvider.getTrustedRoot();
  }
  const resolvedPath = path.resolve(pathInput);
  const raw = await readFile(resolvedPath, "utf8");
  return JSON.parse(raw) as TrustedRoot;
}

async function loadBundle(bundlePath: string): Promise<SigstoreBundle> {
  const resolved = path.resolve(bundlePath);
  const raw = await readFile(resolved, "utf8");
  return JSON.parse(raw) as SigstoreBundle;
}

async function verifyBundle(options: CLIOptions): Promise<void> {
  const [trustedRoot, bundle, artifact] = await Promise.all([
    loadTrustedRoot(options.trustedRootPath),
    loadBundle(options.bundlePath),
    resolveArtifact(options.artifactInput),
  ]);

  const verifier = new SigstoreVerifier();
  await verifier.loadSigstoreRoot(trustedRoot);

  // Extract and verify the artifact digest from the bundle
  let bundleDigestHex: string;
  let bundleDigestBytes: Uint8Array;

  if (bundle.messageSignature) {
    // Regular bundle: digest is in messageSignature
    if (bundle.messageSignature.messageDigest.algorithm !== "SHA2_256") {
      throw new Error(
        `Unsupported message digest algorithm: ${bundle.messageSignature.messageDigest.algorithm}`,
      );
    }

    bundleDigestBytes = base64ToUint8Array(
      bundle.messageSignature.messageDigest.digest,
    );
    bundleDigestHex = Uint8ArrayToHex(bundleDigestBytes).toLowerCase();
  } else if (bundle.dsseEnvelope) {
    // DSSE bundle: digest is in the in-toto statement payload
    const payloadBytes = base64ToUint8Array(bundle.dsseEnvelope.payload);
    const payload = JSON.parse(Uint8ArrayToString(payloadBytes));

    if (!payload.subject || payload.subject.length === 0) {
      throw new Error("DSSE payload has no subject");
    }

    // Find matching subject by comparing artifact digest with all subjects
    let matchedSubject = null;
    for (const subject of payload.subject) {
      const subjectDigest = subject.digest?.["sha256"];
      if (subjectDigest && artifact.digestHex === subjectDigest.toLowerCase()) {
        matchedSubject = subject;
        break;
      }
    }

    if (!matchedSubject) {
      throw new Error(
        `Artifact digest ${artifact.digestHex} does not match any subject in DSSE payload`
      );
    }

    bundleDigestHex = matchedSubject.digest["sha256"].toLowerCase();

    // Convert hex digest to bytes for verification target
    bundleDigestBytes = hexToUint8Array(bundleDigestHex);
  } else {
    throw new Error("Bundle does not contain a message signature or DSSE envelope");
  }

  // For non-DSSE bundles, verify the digest matches
  if (bundle.messageSignature && artifact.digestHex !== bundleDigestHex) {
    throw new Error(
      "Artifact digest does not match the digest embedded in the bundle.",
    );
  }

  const verificationTarget =
    artifact.type === "file" ? artifact.data : bundleDigestBytes;
  const isDigestOnly = artifact.type === "digest";

  await verifier.verifyArtifact(
    options.certificateIdentity,
    options.certificateOidcIssuer,
    bundle,
    verificationTarget,
    isDigestOnly,
  );
}

async function main(): Promise<void> {
  try {
    const options = parseArgs(process.argv.slice(2));
    await verifyBundle(options);
    console.log("Bundle verification succeeded.");
  } catch (error) {
    if (error instanceof Error) {
      console.error(error.message);
    } else {
      console.error(error);
    }
    process.exitCode = 1;
  }
}

await main();
