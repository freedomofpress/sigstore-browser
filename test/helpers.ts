import type { ManagedKeyVector } from "./corpus/data.ts";

export function vector(vectors: ManagedKeyVector[], id: string): ManagedKeyVector {
  const found = vectors.find((candidate) => candidate.id === id);
  if (!found) {
    throw new Error(`no vector ${id}`);
  }
  return found;
}

export function base64ToBytes(encoded: string): Uint8Array {
  const decoded = atob(encoded);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

// Uncoded errors remain test failures instead of being mistaken for expected rejections.
export async function reason(check: Promise<unknown> | (() => unknown)): Promise<string> {
  try {
    if (typeof check === "function") {
      await check();
    } else {
      await check;
    }
    return "accept";
  } catch (error) {
    if (error instanceof Error && "code" in error && typeof error.code === "string") {
      return error.code;
    }
    throw error;
  }
}
