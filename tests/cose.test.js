const cbor = require("../cbor.js");
const cose = require("../cose.js");

let failures = 0;
function check(cond, msg) {
  if (cond) console.log("ok:", msg);
  else {
    console.error("FAIL:", msg);
    failures++;
  }
}

(async () => {
  const kp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const coseKeyHex = cbor.toHex(cbor.encode(new Map([[1, 1], [-1, 6], [3, -8], [-2, rawPub]])));

  const addressBytes = new Uint8Array(29).fill(0xab);
  const protectedBytes = cose.encodeProtectedHeader({ addressBytes });
  const unprotectedMap = cose.encodeUnprotectedHeader({ hashed: false });

  const payloadObj = { uri: "https://arsmagna.xyz", nonce: "abc123", timestamp: 1234567890, action: "login" };
  const payloadBytes = new TextEncoder().encode(JSON.stringify(payloadObj));

  const sigStructure = cose.buildSigStructure(protectedBytes, payloadBytes);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, sigStructure));
  const sign1Hex = cbor.toHex(cbor.encode([protectedBytes, unprotectedMap, payloadBytes, signature]));

  const decodedSign1 = cose.decodeSign1(sign1Hex);
  const decodedKey = cose.decodeKey(coseKeyHex);

  check(decodedSign1.alg === -8, "decoded alg is EdDSA (-8)");
  check(cbor.toHex(decodedSign1.address) === cbor.toHex(addressBytes), "decoded address matches what was signed");
  check(decodedSign1.hashed === false, "decoded hashed flag is false");
  check(JSON.parse(new TextDecoder().decode(decodedSign1.payload)).action === "login", "decoded payload JSON round-trips");

  const result = await cose.verifySign1(decodedSign1, decodedKey);
  check(result.valid === true, "genuine signature verifies");

  // tamper with payload after signing -> must fail
  const tamperedPayload = new TextEncoder().encode(JSON.stringify({ ...payloadObj, action: "prove-ownership" }));
  const tamperedHex = cbor.toHex(cbor.encode([protectedBytes, unprotectedMap, tamperedPayload, signature]));
  const tamperedResult = await cose.verifySign1(cose.decodeSign1(tamperedHex), decodedKey);
  check(tamperedResult.valid === false, "tampered payload does not verify");

  // wrong public key -> must fail
  const otherKp = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const otherRawPub = new Uint8Array(await crypto.subtle.exportKey("raw", otherKp.publicKey));
  const wrongKey = cose.decodeKey(cbor.toHex(cbor.encode(new Map([[1, 1], [-1, 6], [3, -8], [-2, otherRawPub]]))));
  const wrongKeyResult = await cose.verifySign1(decodedSign1, wrongKey);
  check(wrongKeyResult.valid === false, "wrong public key does not verify");

  console.log(failures === 0 ? "\ncose.js: ALL TESTS PASSED" : "\ncose.js: " + failures + " TEST(S) FAILED");
  process.exitCode = failures === 0 ? 0 : 1;
})().catch((e) => {
  console.error("ERROR", e);
  process.exitCode = 1;
});
