const cbor = require("../cbor.js");

let failures = 0;
function eq(a, b, msg) {
  const norm = (v) =>
    JSON.stringify(v, (k, x) =>
      x instanceof Uint8Array ? cbor.toHex(x) : x instanceof Map ? Array.from(x.entries()) : x
    );
  if (norm(a) === norm(b)) {
    console.log("ok:", msg);
  } else {
    console.error("FAIL:", msg, norm(a), "!=", norm(b));
    failures++;
  }
}

// unsigned ints across all header-length boundaries
[0, 1, 23, 24, 25, 255, 256, 65535, 65536, 4294967295, 4294967296, Number.MAX_SAFE_INTEGER].forEach((n) =>
  eq(cbor.decode(cbor.encode(n)), n, "uint " + n)
);

// negative ints across the same boundaries
[-1, -24, -25, -256, -257, -65536].forEach((n) => eq(cbor.decode(cbor.encode(n)), n, "negint " + n));

const bs = new Uint8Array([1, 2, 3, 255, 0]);
eq(cbor.decode(cbor.encode(bs)), bs, "byte string round-trips");
eq(cbor.decode(cbor.encode("hello CIP-93")), "hello CIP-93", "text string round-trips");
eq(cbor.decode(cbor.encode(true)), true, "true round-trips");
eq(cbor.decode(cbor.encode(false)), false, "false round-trips");
eq(cbor.decode(cbor.encode(null)), null, "null round-trips");
eq(cbor.decode(cbor.encode([1, "a", bs, true])), [1, "a", bs, true], "array round-trips");

// mixed int/text keys in one map — this is exactly what COSE headers need
const m = new Map([[1, -8], ["address", bs]]);
const decMap = cbor.decode(cbor.encode(m));
eq(decMap instanceof Map, true, "map decodes to a Map, not a plain object");
eq(decMap.get(1), -8, "map preserves an integer key");
eq(decMap.get("address"), bs, "map preserves a text key");

// nested: a bstr containing an embedded CBOR-encoded map — the exact
// shape of COSE's "protected header" field
const protectedBytes = cbor.encode(new Map([[1, -8], ["address", bs]]));
const outer = cbor.decode(cbor.encode([protectedBytes, new Map(), bs, bs]));
eq(cbor.decode(outer[0]).get("address"), bs, "nested protected-header bstr round-trips");

eq(cbor.toHex(new Uint8Array([0, 255, 16])), "00ff10", "toHex");
eq(Array.from(cbor.fromHex("00ff10")), [0, 255, 16], "fromHex");

try {
  cbor.decode(new Uint8Array([0x9f]));
  console.error("FAIL: should reject indefinite-length items");
  failures++;
} catch (e) {
  console.log("ok: rejects indefinite-length items ->", e.message);
}

try {
  cbor.decode(new Uint8Array([0x01, 0x02]));
  console.error("FAIL: should reject trailing bytes");
  failures++;
} catch (e) {
  console.log("ok: rejects trailing bytes ->", e.message);
}

console.log(failures === 0 ? "\ncbor.js: ALL TESTS PASSED" : "\ncbor.js: " + failures + " TEST(S) FAILED");
process.exitCode = failures === 0 ? 0 : 1;
