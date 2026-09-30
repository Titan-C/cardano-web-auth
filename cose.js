/**
 * cose.js — COSE_Sign1 / COSE_Key handling, per CIP-8 (which is itself a
 * profile of COSE / RFC 8152).
 *
 * GENERIC CIP-8/COSE PLUMBING. Nothing here knows about nonces, sessions,
 * or "signup" vs "login" — it only knows how to build the bytes a wallet
 * is asked to sign, and how to check a signature against them. This is
 * the layer you'd reuse for ANY CIP-8 message-signing use case, not just
 * this authentication scheme.
 *
 * References:
 *   - CIP-8  (Message Signing): https://cips.cardano.org/cip/CIP-8
 *   - CIP-30 (Wallet Web Bridge, defines signData / DataSignature):
 *       https://cips.cardano.org/cip/CIP-30
 *   - RFC 8152 (COSE)
 *
 * Structures (CDDL, from CIP-8):
 *
 *   COSE_Sign1 = [
 *     protected   : bstr .cbor header_map,
 *     unprotected : header_map,
 *     payload     : bstr / nil,
 *     signature   : bstr
 *   ]
 *
 *   COSE_Key (RFC 8152 §13.2, OKP subset used for Ed25519) =
 *     { 1: kty, 2: kid, 3: alg, -1: crv, -2: x }
 *
 * CIP-8 protected-header conventions we rely on:
 *   - `1` (alg)      -> `-8` (EdDSA), a standard COSE header label
 *   - `"address"`    -> raw Cardano address bytes (CIP-8 §"Signing and
 *                       Verification process", NOT a standard COSE label —
 *                       it's the text string "address" used as a map key)
 * and one CIP-8 unprotected-header convention:
 *   - `"hashed"`     -> bool, whether `payload` is the real message or its
 *                       Blake2b-224 hash (used for hardware-wallet-sized
 *                       payloads). This demo only supports hashed=false —
 *                       see the README for why.
 */
(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory(require("./cbor.js"));
  } else {
    root.CoseAuth = factory(root.CborCodec);
  }
})(typeof window !== "undefined" ? window : globalThis, function (cbor) {
  "use strict";

  const ALG_EDDSA = -8; // COSE algorithm identifier for EdDSA (RFC 8152 §8.2)
  const KTY_OKP = 1; // COSE key type: Octet Key Pair
  const CRV_ED25519 = 6; // COSE elliptic curve identifier for Ed25519

  /**
   * Decode a hex-encoded COSE_Sign1 (as returned in DataSignature.signature
   * from CIP-30's `signData`) into its logical parts.
   */
  function decodeSign1(hex) {
    const bytes = cbor.fromHex(hex);
    let arr = cbor.decode(bytes);
    if (arr && typeof arr === "object" && arr.tag !== undefined) {
      // Some encoders wrap COSE_Sign1 in CBOR tag 18. Unwrap it if present;
      // don't require it, since CIP-8 payloads are commonly untagged.
      arr = arr.value;
    }
    if (!Array.isArray(arr) || arr.length !== 4) {
      throw new Error("cose: not a well-formed COSE_Sign1 (expected a 4-element array)");
    }
    const [protectedBytes, unprotected, payload, signature] = arr;
    if (!(protectedBytes instanceof Uint8Array)) {
      throw new Error("cose: COSE_Sign1[0] (protected) must be a byte string");
    }
    if (!(unprotected instanceof Map)) {
      throw new Error("cose: COSE_Sign1[1] (unprotected) must be a map");
    }
    if (payload !== null && !(payload instanceof Uint8Array)) {
      throw new Error("cose: COSE_Sign1[2] (payload) must be a byte string or nil");
    }
    if (!(signature instanceof Uint8Array)) {
      throw new Error("cose: COSE_Sign1[3] (signature) must be a byte string");
    }

    const protectedMap = protectedBytes.length === 0 ? new Map() : cbor.decode(protectedBytes);
    if (!(protectedMap instanceof Map)) {
      throw new Error("cose: protected header does not decode to a map");
    }

    return {
      protectedBytes, // keep the raw bytes — Sig_structure needs them verbatim
      protectedMap,
      unprotected,
      payload,
      signature,
      alg: protectedMap.get(1),
      address: protectedMap.get("address") || null, // raw address bytes, if present
      hashed: unprotected.get("hashed") === true,
    };
  }

  /**
   * Decode a hex-encoded COSE_Key (DataSignature.key from signData) into
   * { kty, crv, alg, x } and validate it's the Ed25519 shape we expect.
   */
  function decodeKey(hex) {
    const bytes = cbor.fromHex(hex);
    const map = cbor.decode(bytes);
    if (!(map instanceof Map)) throw new Error("cose: COSE_Key does not decode to a map");
    const kty = map.get(1);
    const crv = map.get(-1);
    const x = map.get(-2);
    if (kty !== KTY_OKP) {
      throw new Error("cose: unsupported COSE_Key kty " + kty + " (expected OKP=" + KTY_OKP + ")");
    }
    if (crv !== CRV_ED25519) {
      throw new Error("cose: unsupported curve " + crv + " (expected Ed25519=" + CRV_ED25519 + ")");
    }
    if (!(x instanceof Uint8Array) || x.length !== 32) {
      throw new Error("cose: COSE_Key x-coordinate must be a 32-byte Ed25519 public key");
    }
    return { kty, crv, alg: map.get(3), publicKey: x };
  }

  /**
   * Build the Sig_structure that was ACTUALLY signed (CIP-8's "Signing and
   * Verification target format" — this is COSE's Sig_structure for the
   * Signature1 context, RFC 8152 §4.4). This is NOT the same bytes as the
   * COSE_Sign1 array itself.
   *
   *   Sig_structure = [
   *     "Signature1",
   *     body_protected : bstr,   ; the protected header bytes, verbatim
   *     external_aad    : bstr,  ; empty in CIP-8's usage
   *     payload         : bstr
   *   ]
   */
  function buildSigStructure(protectedBytes, payloadBytes, externalAad) {
    return cbor.encode([
      "Signature1",
      protectedBytes,
      externalAad || new Uint8Array(0),
      payloadBytes,
    ]);
  }

  /**
   * Verify a decoded COSE_Sign1 against a decoded COSE_Key.
   * Returns { valid: boolean, reason?: string }.
   *
   * Uses the browser/Node Web Crypto API's native Ed25519 support
   * (SubtleCrypto, "Secure Curves" spec) rather than a hand-rolled Ed25519
   * implementation. Given how easy it is to get elliptic-curve code subtly
   * wrong, and how little independent review a demo repo's crypto code
   * gets, leaning on the platform's audited implementation is the safer
   * choice for a reference implementation — see the README for the
   * trade-off this implies (browser support requirements).
   */
  async function verifySign1(sign1, key) {
    if (sign1.alg !== ALG_EDDSA) {
      return { valid: false, reason: "unsupported alg " + sign1.alg + " (expected EdDSA=" + ALG_EDDSA + ")" };
    }
    if (sign1.hashed) {
      return {
        valid: false,
        reason:
          "payload is hash-signed (unprotected 'hashed'=true); this demo only " +
          "verifies direct (non-hashed) payloads — see README",
      };
    }
    if (!(sign1.payload instanceof Uint8Array)) {
      return { valid: false, reason: "COSE_Sign1 has a nil payload; this scheme requires an explicit payload" };
    }
    if (!crypto || !crypto.subtle || !crypto.subtle.importKey) {
      return { valid: false, reason: "Web Crypto (SubtleCrypto) is not available in this environment" };
    }

    const sigStructure = buildSigStructure(sign1.protectedBytes, sign1.payload);

    let cryptoKey;
    try {
      cryptoKey = await crypto.subtle.importKey("raw", key.publicKey, { name: "Ed25519" }, false, ["verify"]);
    } catch (e) {
      return {
        valid: false,
        reason:
          "this browser's Web Crypto doesn't support Ed25519 (" + e.message + "). " +
          "Try a current Chrome, Firefox, or Safari.",
      };
    }

    const ok = await crypto.subtle.verify({ name: "Ed25519" }, cryptoKey, sign1.signature, sigStructure);
    return ok ? { valid: true } : { valid: false, reason: "signature does not match" };
  }

  /**
   * Build an unsigned COSE_Sign1 + wrap-ready structure, for tests and for
   * the mock backend's own understanding of what a wallet will produce.
   * Real signing always happens in the wallet (see wallet.js) — this is
   * only used by the self-tests in cose.test.js to exercise verifySign1
   * without a real wallet attached.
   */
  function encodeProtectedHeader({ addressBytes }) {
    const m = new Map();
    m.set(1, ALG_EDDSA);
    if (addressBytes) m.set("address", addressBytes);
    return cbor.encode(m);
  }

  function encodeUnprotectedHeader({ hashed }) {
    const m = new Map();
    m.set("hashed", !!hashed);
    return m;
  }

  return {
    ALG_EDDSA,
    KTY_OKP,
    CRV_ED25519,
    decodeSign1,
    decodeKey,
    buildSigStructure,
    verifySign1,
    encodeProtectedHeader,
    encodeUnprotectedHeader,
  };
});
