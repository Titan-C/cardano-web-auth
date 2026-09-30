/**
 * protocol.js — PROTOCOL-SPECIFIC LOGIC for the wallet-native auth scheme.
 *
 * Everything in cbor.js/cose.js/wallet.js is generic CIP-8/CIP-30 plumbing
 * that would look the same for any wallet-signing use case. This file is
 * the opposite: it only makes sense for THIS auth scheme. It defines:
 *
 *   1. the structured JSON payload shape (the thing CIP-93 asks dApps to
 *      standardize instead of ad-hoc static strings), and
 *   2. the six-stage verification pipeline, run in the exact order fixed
 *      by the M1 spec: parse COSE -> address -> nonce -> timestamp -> uri
 *      -> action -> signature.
 *
 * NOTE ON PAYLOAD SHAPE: the M1 spec document (not included in this demo)
 * is the source of truth for the exact field names. The shape below
 * ({ uri, nonce, timestamp, action }) is inferred from the M2 design
 * doc's own vocabulary — it names exactly these fields when describing the
 * verification order — but reconcile it against the actual M1 spec before
 * treating it as final.
 *
 * WHY SIGNATURE IS CHECKED LAST, NOT FIRST: it looks backwards to validate
 * a payload's *claims* before confirming anyone actually signed it. The
 * reasoning: every earlier stage is a cheap, local check against data the
 * request merely CLAIMS (an unverified nonce lookup, a string comparison).
 * Ordering them before the one genuinely expensive/cryptographic stage
 * means a malformed or replayed request fails fast, AND — just as
 * important for a reference implementation — the demo can tell you
 * exactly *which* claim was wrong ("uri mismatch") instead of a single
 * opaque "invalid signature" that would also fire if any of those cheaper
 * checks failed. The signature check is still what makes any of it
 * trustworthy: nothing here treats a request as authenticated until it
 * passes.
 */
(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory(require("./cbor.js"), require("./cose.js"));
  } else {
    root.AuthProtocol = factory(root.CborCodec, root.CoseAuth);
  }
})(typeof window !== "undefined" ? window : globalThis, function (cbor, cose) {
  "use strict";

  const ACTIONS = ["signup", "login", "prove-ownership"];
  const NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes — matches the "short-lived nonce" note in the design doc
  const CLOCK_SKEW_TOLERANCE_MS = 30 * 1000;

  /** Build the exact bytes a wallet will be asked to sign for one auth step. */
  function buildPayload({ uri, nonce, action, timestamp }) {
    if (!ACTIONS.includes(action)) throw new Error("protocol: unknown action " + action);
    const obj = { uri, nonce, action, timestamp };
    const json = JSON.stringify(obj);
    return { obj, bytes: new TextEncoder().encode(json) };
  }

  /**
   * Run the full pipeline. `backend` must implement:
   *   getNonceRecord(nonce)          -> record | undefined
   *   consumeNonce(nonce)            -> marks it used (single use)
   *   findAccountByAddressHex(hex)   -> account | undefined
   *
   * Returns { ok: boolean, stages: [{name, ok, detail}], payload, address }
   * — `stages` always lists every stage attempted, in order, so the UI can
   * render the whole pipeline and highlight exactly where it stopped.
   */
  async function runVerificationPipeline({ sign1Hex, keyHex, backend }) {
    const stages = [];
    function record(name, ok, detail) {
      stages.push({ name, ok, detail });
      return ok;
    }

    // -- stage 0: parse COSE --------------------------------------------
    let sign1, key, payload;
    try {
      sign1 = cose.decodeSign1(sign1Hex);
      key = cose.decodeKey(keyHex);
      if (!(sign1.payload instanceof Uint8Array)) {
        throw new Error("COSE_Sign1 payload is nil; this scheme requires an explicit payload");
      }
      payload = JSON.parse(new TextDecoder().decode(sign1.payload));
    } catch (e) {
      record("parse", false, e.message);
      return { ok: false, stages, payload: null, address: null };
    }
    record("parse", true, "decoded COSE_Sign1 + COSE_Key, payload is valid JSON");

    // -- stage 1: address ---------------------------------------------------
    // A business-logic check, deliberately independent of the nonce store:
    // does the signed address make sense for the action being claimed?
    const addressHex = sign1.address ? cbor.toHex(sign1.address) : null;
    if (!addressHex) {
      record("address", false, "protected header has no 'address' entry");
      return { ok: false, stages, payload, address: null };
    }
    const account = backend.findAccountByAddressHex(addressHex);
    if (payload.action === "signup" && account) {
      record("address", false, shorten(addressHex) + " already has an account — did you mean to log in?");
      return { ok: false, stages, payload, address: addressHex };
    }
    if (payload.action !== "signup" && !account) {
      record("address", false, "no account for " + shorten(addressHex) + " — did you mean to sign up?");
      return { ok: false, stages, payload, address: addressHex };
    }
    record("address", true, "address " + shorten(addressHex) + " is consistent with action '" + payload.action + "'");

    // -- stage 2: nonce -------------------------------------------------
    // Checks BOTH that the nonce is real/unused AND that it was issued
    // for this exact address — otherwise a signature from an unrelated
    // (but validly-registered) address could satisfy someone else's nonce.
    const nonceRecord = backend.getNonceRecord(payload.nonce);
    if (!nonceRecord) {
      record("nonce", false, "nonce " + shorten(payload.nonce) + " is unknown or was already used");
      return { ok: false, stages, payload, address: addressHex };
    }
    if (nonceRecord.consumed) {
      record("nonce", false, "nonce " + shorten(payload.nonce) + " was already consumed (replay attempt)");
      return { ok: false, stages, payload, address: addressHex };
    }
    if (nonceRecord.addressHex !== addressHex) {
      record("nonce", false, "nonce was issued for a different address than the one that signed this payload");
      return { ok: false, stages, payload, address: addressHex };
    }
    record("nonce", true, "nonce is known, unused, and bound to this address");

    // -- stage 3: timestamp -------------------------------------------------
    const now = Date.now();
    const age = now - payload.timestamp;
    if (typeof payload.timestamp !== "number" || Number.isNaN(payload.timestamp)) {
      record("timestamp", false, "payload.timestamp is missing or not a number");
      return { ok: false, stages, payload, address: addressHex };
    }
    if (age < -CLOCK_SKEW_TOLERANCE_MS) {
      record("timestamp", false, "timestamp is in the future (" + Math.round(-age / 1000) + "s ahead)");
      return { ok: false, stages, payload, address: addressHex };
    }
    if (now - nonceRecord.issuedAt > NONCE_TTL_MS) {
      record("timestamp", false, "nonce expired (" + Math.round((now - nonceRecord.issuedAt) / 1000) + "s old, limit " + NONCE_TTL_MS / 1000 + "s)");
      return { ok: false, stages, payload, address: addressHex };
    }
    record("timestamp", true, "within the nonce's validity window");

    // -- stage 4: uri (domain binding) --------------------------------------
    // nonceRecord.origin was captured by the backend itself at nonce-issuance
    // time (see mock-backend.js) — it is NEVER taken from client input, the
    // same way a real server would trust its own observed Origin header over
    // anything in the request body. That's what makes this check meaningful:
    // payload.uri is attacker/dApp-controlled, nonceRecord.origin is not.
    if (payload.uri !== nonceRecord.origin) {
      record(
        "uri",
        false,
        "payload uri (" + payload.uri + ") does not match the origin this nonce was issued for (" + nonceRecord.origin + ")"
      );
      return { ok: false, stages, payload, address: addressHex };
    }
    record("uri", true, "payload uri matches the nonce's bound origin");

    // -- stage 5: action (server-committed) ---------------------------------
    if (payload.action !== nonceRecord.action) {
      record(
        "action",
        false,
        "payload action (" + payload.action + ") does not match the action this nonce was issued for (" + nonceRecord.action + ")"
      );
      return { ok: false, stages, payload, address: addressHex };
    }
    record("action", true, "payload action matches the nonce's committed action");

    // -- stage 6: signature (the expensive, authoritative check) -----------
    const sigResult = await cose.verifySign1(sign1, key);
    if (!sigResult.valid) {
      record("signature", false, sigResult.reason);
      return { ok: false, stages, payload, address: addressHex };
    }
    record("signature", true, "Ed25519 signature verified");

    // Only now do we consume the nonce — a failed verification anywhere
    // above leaves it intact so the wallet can legitimately retry.
    backend.consumeNonce(payload.nonce);

    return { ok: true, stages, payload, address: addressHex };
  }

  function shorten(hex) {
    return hex.length > 16 ? hex.slice(0, 8) + "\u2026" + hex.slice(-6) : hex;
  }

  return { ACTIONS, NONCE_TTL_MS, buildPayload, runVerificationPipeline, shorten };
});
