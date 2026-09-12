import { ASN1Obj, uint8ArrayEqual } from "@freedomofpress/crypto-browser";

// Deeper nesting than any X.509 or RFC 3161 structure needs; the recursive parser would exhaust the stack around 3500.
const MAX_DEPTH = 32;

// Iteratively walks the TLV tree the same way ASN1Obj.parseBuffer recurses (constructed values, and OCTET STRING
// contents that parse cleanly) and rejects nesting deeper than MAX_DEPTH before the recursive parser runs.
function checkDepth(buf: Uint8Array): void {
  const stack: { end: number; octet: boolean }[] = [{ end: buf.length, octet: false }];
  let pos = 0;

  // The parser treats an OCTET STRING with unparsable content as primitive, so unwind to the innermost one.
  const unwind = (): void => {
    let frame;
    while ((frame = stack.pop()) && !frame.octet);
    if (!frame) throw new Error("Invalid DER encoding");
    pos = frame.end;
  };

  while (stack.length > 0) {
    const top = stack[stack.length - 1];
    if (pos >= top.end) {
      if (pos > top.end) unwind();
      else stack.pop();
      continue;
    }
    const tag = buf[pos];
    const first = buf[pos + 1];
    let header = 2;
    let len = first;
    if (first & 0x80) {
      const count = first & 0x7f;
      len = 0;
      for (let i = 0; i < count; i++) len = len * 256 + buf[pos + 2 + i];
      header += count;
      if (count === 0 || count > 6 || len === 0) len = NaN;
    }
    const end = pos + header + len;
    if (tag === 0 || (tag & 0x1f) === 0x1f || !(end <= top.end)) {
      unwind();
      continue;
    }
    if (tag & 0x20 || (tag === 0x04 && len > 0)) {
      if (stack.length > MAX_DEPTH) throw new Error("ASN.1 nesting too deep");
      stack.push({ end, octet: tag === 0x04 });
      pos += header;
    } else {
      pos = end;
    }
  }
}

// Parses DER strictly: bounded nesting depth, and the re-encoding must reproduce the input byte for byte,
// which rejects trailing bytes and non-canonical (BER) encodings.
export function parseDER(buf: Uint8Array): ASN1Obj {
  checkDepth(buf);
  const obj = ASN1Obj.parseBuffer(buf);
  if (!uint8ArrayEqual(obj.toDER(), buf)) {
    throw new Error("Invalid DER encoding");
  }
  return obj;
}
