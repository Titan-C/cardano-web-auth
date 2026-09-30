/**
 * cbor.js — a deliberately small CBOR encoder/decoder.
 *
 * GENERIC PLUMBING — nothing here knows about wallets, Cardano, or auth.
 * It only knows the CBOR data model (RFC 8949).
 *
 * Why hand-rolled instead of a real CBOR library:
 * the M2 design doc treats COSE_Sign1 parsing as security-sensitive code
 * and asks for it to be "small, tested against known-good payloads, and
 * reviewed carefully rather than hand-waved." A full CBOR library has to
 * handle indefinite-length items, tags, floats, bignums, and more — most
 * of which COSE_Sign1 / COSE_Key never use. This file implements only the
 * subset those two structures actually need:
 *
 *   - unsigned integers   (major type 0)
 *   - negative integers   (major type 1)
 *   - byte strings        (major type 2, definite length only)
 *   - text strings        (major type 3, definite length only)
 *   - arrays              (major type 4, definite length only)
 *   - maps                (major type 5, definite length only)
 *   - simple values        false / true / null (major type 7)
 *   - tags                (major type 6) — decoded and exposed, not required
 *
 * Indefinite-length items and floating point are intentionally NOT
 * supported. If you feed this decoder a payload that uses them, it throws
 * rather than silently doing the wrong thing.
 *
 * Maps decode to a JS `Map` (not a plain object) because COSE headers mix
 * integer and text-string keys in the same map (e.g. `1` for "alg" next to
 * `"address"`), and plain objects can't represent that unambiguously.
 */
(function (root) {
  "use strict";

  // ---- encoding -----------------------------------------------------

  function encode(value) {
    const chunks = [];
    encodeValue(value, chunks);
    return concatBytes(chunks);
  }

  function encodeValue(value, chunks) {
    if (value instanceof Uint8Array) {
      encodeHead(2, value.length, chunks);
      chunks.push(value);
    } else if (typeof value === "string") {
      const bytes = new TextEncoder().encode(value);
      encodeHead(3, bytes.length, chunks);
      chunks.push(bytes);
    } else if (typeof value === "number" || typeof value === "bigint") {
      encodeInt(value, chunks);
    } else if (typeof value === "boolean") {
      chunks.push(new Uint8Array([value ? 0xf5 : 0xf4]));
    } else if (value === null || value === undefined) {
      chunks.push(new Uint8Array([0xf6]));
    } else if (Array.isArray(value)) {
      encodeHead(4, value.length, chunks);
      for (const item of value) encodeValue(item, chunks);
    } else if (value instanceof Map) {
      encodeHead(5, value.size, chunks);
      for (const [k, v] of value.entries()) {
        encodeValue(k, chunks);
        encodeValue(v, chunks);
      }
    } else if (typeof value === "object" && value.tag !== undefined && "value" in value) {
      // { tag: n, value: ... } — explicit CBOR tag wrapper, see decode()
      encodeHead(6, value.tag, chunks);
      encodeValue(value.value, chunks);
    } else {
      throw new TypeError("cbor.encode: unsupported value: " + JSON.stringify(value));
    }
  }

  function encodeInt(value, chunks) {
    let n = typeof value === "bigint" ? value : BigInt(value);
    if (n >= 0n) {
      encodeHead(0, n, chunks);
    } else {
      encodeHead(1, -1n - n, chunks);
    }
  }

  // Writes a major-type/length "head". `len` may be a number or BigInt.
  function encodeHead(majorType, len, chunks) {
    const n = typeof len === "bigint" ? len : BigInt(len);
    const top = majorType << 5;
    if (n < 24n) {
      chunks.push(new Uint8Array([top | Number(n)]));
    } else if (n < 256n) {
      chunks.push(new Uint8Array([top | 24, Number(n)]));
    } else if (n < 65536n) {
      const b = new Uint8Array(3);
      b[0] = top | 25;
      new DataView(b.buffer).setUint16(1, Number(n));
      chunks.push(b);
    } else if (n < 4294967296n) {
      const b = new Uint8Array(5);
      b[0] = top | 26;
      new DataView(b.buffer).setUint32(1, Number(n));
      chunks.push(b);
    } else {
      const b = new Uint8Array(9);
      b[0] = top | 27;
      new DataView(b.buffer).setBigUint64(1, n);
      chunks.push(b);
    }
  }

  function concatBytes(chunks) {
    let total = 0;
    for (const c of chunks) total += c.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      out.set(c, offset);
      offset += c.length;
    }
    return out;
  }

  // ---- decoding -------------------------------------------------------

  // decode(bytes) -> value (throws if trailing bytes remain)
  // decodeAt(bytes, offset) -> { value, offset } (does NOT require the
  // whole buffer to be consumed — useful when a bstr contains a nested
  // CBOR-encoded map, as COSE's "protected header" does).
  function decode(bytes) {
    const { value, offset } = decodeAt(bytes, 0);
    if (offset !== bytes.length) {
      throw new Error(
        "cbor.decode: " + (bytes.length - offset) + " trailing byte(s) after top-level value"
      );
    }
    return value;
  }

  function decodeAt(bytes, offset) {
    if (offset >= bytes.length) throw new Error("cbor.decode: unexpected end of input");
    const initial = bytes[offset];
    const majorType = initial >> 5;
    const infoBits = initial & 0x1f;

    if (infoBits === 31) {
      throw new Error("cbor.decode: indefinite-length items are not supported");
    }

    const { len, next } = readLength(bytes, offset, infoBits);

    switch (majorType) {
      case 0: // unsigned int
        return { value: len <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(len) : len, offset: next };
      case 1: { // negative int
        const n = -1n - len;
        return { value: n >= BigInt(Number.MIN_SAFE_INTEGER) ? Number(n) : n, offset: next };
      }
      case 2: { // byte string
        const end = next + Number(len);
        assertInBounds(bytes, end);
        return { value: bytes.slice(next, end), offset: end };
      }
      case 3: { // text string
        const end = next + Number(len);
        assertInBounds(bytes, end);
        return { value: new TextDecoder().decode(bytes.slice(next, end)), offset: end };
      }
      case 4: { // array
        const count = Number(len);
        const arr = new Array(count);
        let o = next;
        for (let i = 0; i < count; i++) {
          const r = decodeAt(bytes, o);
          arr[i] = r.value;
          o = r.offset;
        }
        return { value: arr, offset: o };
      }
      case 5: { // map
        const count = Number(len);
        const map = new Map();
        let o = next;
        for (let i = 0; i < count; i++) {
          const k = decodeAt(bytes, o);
          const v = decodeAt(bytes, k.offset);
          map.set(k.value, v.value);
          o = v.offset;
        }
        return { value: map, offset: o };
      }
      case 6: { // tag — decode and keep, don't require any particular tag
        const inner = decodeAt(bytes, next);
        return { value: { tag: Number(len), value: inner.value }, offset: inner.offset };
      }
      case 7: { // simple values we care about
        switch (infoBits) {
          case 20: return { value: false, offset: next };
          case 21: return { value: true, offset: next };
          case 22: return { value: null, offset: next };
          default:
            throw new Error("cbor.decode: unsupported simple value (info " + infoBits + ")");
        }
      }
      default:
        throw new Error("cbor.decode: unsupported major type " + majorType);
    }
  }

  function readLength(bytes, offset, infoBits) {
    if (infoBits < 24) return { len: BigInt(infoBits), next: offset + 1 };
    assertInBounds(bytes, offset + 1);
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    switch (infoBits) {
      case 24:
        assertInBounds(bytes, offset + 2);
        return { len: BigInt(dv.getUint8(offset + 1)), next: offset + 2 };
      case 25:
        assertInBounds(bytes, offset + 3);
        return { len: BigInt(dv.getUint16(offset + 1)), next: offset + 3 };
      case 26:
        assertInBounds(bytes, offset + 5);
        return { len: BigInt(dv.getUint32(offset + 1)), next: offset + 5 };
      case 27:
        assertInBounds(bytes, offset + 9);
        return { len: dv.getBigUint64(offset + 1), next: offset + 9 };
      default:
        throw new Error("cbor.decode: reserved additional-info value " + infoBits);
    }
  }

  function assertInBounds(bytes, end) {
    if (end > bytes.length) throw new Error("cbor.decode: unexpected end of input");
  }

  // ---- hex helpers (used everywhere COSE hex strings come in/out) -----

  function toHex(bytes) {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  function fromHex(hex) {
    if (hex.length % 2 !== 0) throw new Error("cbor.fromHex: odd-length hex string");
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      out[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return out;
  }

  const CborCodec = { encode, decode, decodeAt, toHex, fromHex };

  if (typeof module !== "undefined" && module.exports) {
    module.exports = CborCodec;
  } else {
    root.CborCodec = CborCodec;
  }
})(typeof window !== "undefined" ? window : globalThis);
