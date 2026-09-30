const bech32 = require("../bech32.js");

let failures = 0;
function check(cond, msg) {
  if (cond) console.log("ok:", msg);
  else {
    console.error("FAIL:", msg);
    failures++;
  }
}

// Official BIP-173 "valid checksum" test vectors — must decode without throwing.
const VALID = [
  "A12UEL5L",
  "a12uel5l",
  "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
  "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
  "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
  "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
  "?1ezyfcl",
];
for (const v of VALID) {
  try {
    const { hrp } = bech32.decode(v);
    check(true, "BIP-173 vector decodes: " + v + " (hrp=" + hrp + ")");
  } catch (e) {
    check(false, "BIP-173 vector should decode: " + v + " -> " + e.message);
  }
}

// Official BIP-173 "invalid checksum" vectors — must throw.
const INVALID = [
  " 1nwldj5", // HRP character out of range
  "\x7f" + "1axkwrx", // HRP character out of range
  "\x80" + "1eym55h", // HRP character out of range
  "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", // too long
  "pzry9x0s0muk", // no separator
  "1pzry9x0s0muk", // empty HRP
  "x1b4n0q5v", // invalid data character
  "li1dgmt3", // too short checksum
  "de1lg7wt" + "\xff", // invalid character in checksum
  "A1G7SGD8", // checksum calculated with uppercase form of HRP
  "10a06t8", // empty HRP
  "1qzzfhee", // empty HRP
  "a12UEL5L", // mixed case
  "A12uEL5L", // mixed case
  "abcdef1qpzrz9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", // invalid checksum (one char flipped)
  "test1zg69w7y6hn0aqy352euf40x77qddq3dc", // invalid checksum
];
for (const v of INVALID) {
  try {
    bech32.decode(v);
    check(false, "should reject invalid vector: " + JSON.stringify(v));
  } catch (e) {
    check(true, "correctly rejects invalid vector: " + JSON.stringify(v));
  }
}

// round trip arbitrary bytes
for (const len of [1, 16, 28, 29, 32]) {
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = (i * 37 + 11) % 256;
  const encoded = bech32.encode("addr_test", bytes);
  const decoded = bech32.decode(encoded);
  check(decoded.hrp === "addr_test", "round-trip hrp preserved (len=" + len + ")");
  check(Array.from(decoded.bytes).join(",") === Array.from(bytes).join(","), "round-trip bytes preserved (len=" + len + ")");
}

// Cardano address header interpretation (CIP-19)
function addrBytes(headerByte, len = 29) {
  const b = new Uint8Array(len);
  b[0] = headerByte;
  for (let i = 1; i < len; i++) b[i] = (i * 13) % 256;
  return b;
}
check(bech32.cardanoAddressToBech32(addrBytes(0x01)).startsWith("addr1"), "mainnet base address -> addr1...");
check(bech32.cardanoAddressToBech32(addrBytes(0x00)).startsWith("addr_test1"), "testnet base address -> addr_test1...");
check(bech32.cardanoAddressToBech32(addrBytes(0xe1)).startsWith("stake1"), "mainnet reward address -> stake1...");
check(bech32.cardanoAddressToBech32(addrBytes(0xe0)).startsWith("stake_test1"), "testnet reward address -> stake_test1...");
check(bech32.cardanoAddressToBech32(addrBytes(0x81)) === null, "Byron address type returns null (out of scope, falls back to hex)");

console.log(failures === 0 ? "\nbech32.js: ALL TESTS PASSED" : "\nbech32.js: " + failures + " TEST(S) FAILED");
process.exitCode = failures === 0 ? 0 : 1;
