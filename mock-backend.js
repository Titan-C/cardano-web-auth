/**
 * mock-backend.js — a stand-in for the real Clojure backend, running in
 * the same page as the frontend.
 *
 * WHY A CLIENT-SIDE MOCK, NOT A REAL SERVER: the M2 design doc specifies
 * a real Clojure backend (COSE parsing, Ed25519 verification, a durable
 * nonce store). This file is NOT that — it's a demo convenience so the
 * whole flow can be tried by opening one HTML file, no server to stand up.
 * It deliberately mirrors the API surface draft's shape (POST /auth/nonce,
 * POST /auth/verify, GET /auth/session) as plain function calls instead of
 * HTTP endpoints, specifically so porting this to a real server later
 * — Clojure per the design doc, or the Node.js reference implementation
 * planned as a follow-on — is close to a direct translation: each function
 * here is what the corresponding route handler's body would do, minus the
 * HTTP framing itself.
 *
 * Everything is in-memory and resets on page reload — the design doc
 * explicitly calls this acceptable for a demo ("in-memory is fine... call
 * out clearly that production would want something durable"). Consider
 * this that call-out.
 */
(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory(require("./protocol.js"));
  } else {
    root.MockBackend = factory(root.AuthProtocol);
  }
})(typeof window !== "undefined" ? window : globalThis, function (AuthProtocol) {
  "use strict";

  function randomHex(byteLength) {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * @param {() => string} getOrigin - returns the origin to bind new nonces
   *   to. In the real backend this would be the request's Origin header;
   *   here it's a function so callers (and the demo's attack scenarios)
   *   can be explicit about what "the trusted origin" means for a given
   *   nonce request, without ever letting the *client* dictate it for a
   *   real request. See protocol.js's stage-4 comment for why this matters.
   */
  function createBackend(getOrigin) {
    const nonces = new Map(); // nonce -> { nonce, addressHex, action, origin, issuedAt, consumed }
    const accounts = new Map(); // addressHex -> { addressHex, createdAt }
    const sessions = new Map(); // token -> { addressHex, createdAt }

    // ---- POST /auth/nonce -------------------------------------------
    function requestNonce({ addressHex, action }) {
      if (!AuthProtocol.ACTIONS.includes(action)) {
        throw new Error("mock-backend: unknown action '" + action + "'");
      }
      if (!addressHex) throw new Error("mock-backend: requestNonce needs addressHex");
      const nonce = randomHex(16);
      const record = {
        nonce,
        addressHex,
        action,
        origin: getOrigin(), // ALWAYS the backend's own view of the origin
        issuedAt: Date.now(),
        consumed: false,
      };
      nonces.set(nonce, record);
      return { nonce, expiresInMs: AuthProtocol.NONCE_TTL_MS, uri: record.origin };
    }

    // ---- pipeline hooks (see protocol.js for how these are used) -----
    function getNonceRecord(nonce) {
      return nonces.get(nonce);
    }
    function consumeNonce(nonce) {
      const r = nonces.get(nonce);
      if (r) r.consumed = true;
    }
    function findAccountByAddressHex(addressHex) {
      return accounts.get(addressHex);
    }

    const pipelineBackend = { getNonceRecord, consumeNonce, findAccountByAddressHex };

    // ---- POST /auth/verify --------------------------------------------
    async function verify({ sign1Hex, keyHex }) {
      const result = await AuthProtocol.runVerificationPipeline({ sign1Hex, keyHex, backend: pipelineBackend });
      if (!result.ok) return result;

      if (result.payload.action === "signup") {
        accounts.set(result.address, { addressHex: result.address, createdAt: Date.now() });
      }

      // signup and login both establish a session; prove-ownership proves
      // a fresh signature without changing who's logged in.
      if (result.payload.action === "signup" || result.payload.action === "login") {
        const token = randomHex(16);
        sessions.set(token, { addressHex: result.address, createdAt: Date.now() });
        result.sessionToken = token;
      }

      return result;
    }

    // ---- GET /auth/session ---------------------------------------------
    function getSession(token) {
      return sessions.get(token) || null;
    }
    function endSession(token) {
      sessions.delete(token);
    }

    return {
      requestNonce,
      verify,
      getSession,
      endSession,
      findAccountByAddressHex,
      // exposed for the demo UI's "developer view" panel only — a real
      // server would never hand its account/nonce tables to the client
      _inspect: { nonces, accounts, sessions },
    };
  }

  return { createBackend };
});
