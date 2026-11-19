// Engines without WebCrypto Ed25519 (Safari before 17) reject it with NotSupportedError. This module
// imports nothing, so test files can install the stand-in before @freedomofpress/crypto-browser
// first reads crypto.subtle, which it does once.

/** Wraps `subtle` so that every operation on an Ed25519 key or algorithm rejects. */
export function withoutEd25519(subtle: SubtleCrypto): SubtleCrypto {
  return new Proxy(subtle, {
    get(target, prop) {
      const value = Reflect.get(target, prop) as unknown;
      if (typeof value !== "function") {
        return value;
      }
      return (...args: unknown[]) => {
        // importKey takes the algorithm third; the other operations take it first.
        const algorithm = (prop === "importKey" ? args[2] : args[0]) as { name?: string } | string | undefined;
        const name = typeof algorithm === "string" ? algorithm : algorithm?.name;
        if (name === "Ed25519") {
          return Promise.reject(new DOMException("Unrecognized name.", "NotSupportedError"));
        }
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
}

/** Replaces globalThis.crypto.subtle with a copy that has no Ed25519. */
export function removeNativeEd25519(): void {
  const subtle = withoutEd25519(globalThis.crypto.subtle);
  Object.defineProperty(globalThis.crypto, "subtle", { value: subtle, configurable: true });
}
