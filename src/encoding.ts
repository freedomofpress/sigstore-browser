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
export function toArrayBuffer(view: ArrayBufferView): ArrayBuffer {
  const { byteLength } = view;

  if (byteLength === 0) {
    return new ArrayBuffer(0);
  }

  const { buffer, byteOffset } = view;

  if (
    buffer instanceof ArrayBuffer &&
    byteOffset === 0 &&
    byteLength === buffer.byteLength
  ) {
    return buffer;
  }

  const clone = new Uint8Array(byteLength);
  clone.set(new Uint8Array(buffer, byteOffset, byteLength));
  return clone.buffer;
}

export function base64ToUint8Array(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const length = binaryString.length;
  const bytes = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    bytes[i] = binaryString.charCodeAt(i); // Convert binary string to byte array
  }

  return bytes;
}

export function Uint8ArrayToBase64(uint8Array: Uint8Array): string {
  let binaryString = "";

  for (let i = 0; i < uint8Array.length; i++) {
    binaryString += String.fromCharCode(uint8Array[i]);
  }

  return btoa(binaryString);
}

export function hexToUint8Array(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Hex string must have an even length");
  }

  const length = hex.length / 2;
  const uint8Array = new Uint8Array(length);

  for (let i = 0; i < length; i++) {
    uint8Array[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }

  return uint8Array;
}

export function Uint8ArrayToHex(uint8Array: Uint8Array): string {
  let hexString = "";

  for (let i = 0; i < uint8Array.length; i++) {
    let hex = uint8Array[i].toString(16);
    if (hex.length === 1) {
      hex = "0" + hex;
    }
    hexString += hex;
  }

  return hexString;
}

export function stringToUint8Array(str: string): Uint8Array {
  // Defaults to utf-8, but utf-8 is ascii compatible
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

// This is silly, but it is a hack to be consistent with the original test suite
export function Uint8ArrayToString(uint8Array: Uint8Array): string {
  const decoder = new TextDecoder("ascii");
  return decoder.decode(uint8Array);
}

export function readBigInt64BE(
  uint8Array: Uint8Array,
  offset?: number,
): bigint {
  if (offset === undefined) {
    offset = 0;
  }
  const hex = Uint8ArrayToHex(uint8Array.slice(offset, offset + 8));
  return BigInt(`0x${hex}`);
}

export function base64Encode(str: string): string {
  return Uint8ArrayToBase64(stringToUint8Array(str));
}

export function base64Decode(str: string): string {
  return Uint8ArrayToString(base64ToUint8Array(str));
}

export function uint8ArrayEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }

  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}
