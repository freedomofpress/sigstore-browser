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
const PAE_PREFIX = "DSSEv1";

// DSSE Pre-Authentication Encoding
export function preAuthEncoding(
  payloadType: string,
  payload: Uint8Array,
): Uint8Array {
  const prefix = [
    PAE_PREFIX,
    payloadType.length,
    payloadType,
    payload.length,
    "",
  ].join(" ");

  // DSSE spec requires ASCII encoding for the prefix
  // Convert string to ASCII bytes (each char must be < 128)
  const prefixBuffer = new Uint8Array(prefix.length);
  for (let i = 0; i < prefix.length; i++) {
    const charCode = prefix.charCodeAt(i);
    if (charCode > 127) {
      throw new Error(`Invalid character in PAE prefix at position ${i}: charCode ${charCode}`);
    }
    prefixBuffer[i] = charCode;
  }

  // Concatenate prefix and payload
  const combinedArray = new Uint8Array(prefixBuffer.length + payload.length);

  combinedArray.set(prefixBuffer, 0);
  combinedArray.set(payload, prefixBuffer.length);
  return combinedArray;
}
