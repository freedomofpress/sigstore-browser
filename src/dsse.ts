import { concatBytes, stringToUint8Array } from "@freedomofpress/crypto-browser";
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

  // DSSE requires an ASCII prefix.
  const prefixBuffer = stringToUint8Array(prefix);

  // Verify all characters are ASCII (< 128)
  for (let i = 0; i < prefixBuffer.length; i++) {
    if (prefixBuffer[i] > 127) {
      throw new Error(`Invalid non-ASCII character in PAE prefix at position ${i}`);
    }
  }

  return concatBytes(prefixBuffer, payload);
}
