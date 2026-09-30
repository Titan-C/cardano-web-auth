/**
 * wallet.js — GENERIC CIP-30 PLUMBING.
 *
 * Wallet detection, connection, address selection, and the signData
 * call. Nothing in this file knows what a "nonce" or an "action" is —
 * it would look the same if you were building a completely different
 * CIP-8 signing feature. This is the boundary the design doc asks for:
 * "clear boundaries between generic CIP-30/CIP-93 plumbing and
 * protocol-specific logic, so someone... can see what to copy and what
 * to replace." Copy this file as-is; replace protocol.js.
 *
 * Browser-only — reads `window.cardano`, so this file can't run under
 * Node (unlike cbor.js/cose.js/protocol.js/mock-backend.js, which are
 * unit-tested in tests/pipeline.test.js). Keeping the wallet boundary
 * this thin is deliberate: less surface area here means less that can
 * only be exercised by hand, in a real browser, with a real wallet.
 *
 * Reference: CIP-30, https://cips.cardano.org/cip/CIP-30
 */
(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory(require("./cbor.js"));
  } else {
    root.CipWallet = factory(root.CborCodec);
  }
})(typeof window !== "undefined" ? window : globalThis, function (cbor) {
  "use strict";

  /**
   * List CIP-30 wallets injected into window.cardano. A wallet is
   * anything under window.cardano exposing an `enable` function — CIP-30
   * doesn't reserve the namespace beyond that, so we don't hardcode a
   * list of known wallet keys (nami/eternl/etc). That list drifts as
   * wallets appear, get renamed, or stop being maintained; asking the
   * page itself is the only thing that stays correct.
   */
  function detectWallets() {
    if (typeof window === "undefined" || !window.cardano) return [];
    return Object.keys(window.cardano)
      .filter((key) => {
        const w = window.cardano[key];
        return w && typeof w.enable === "function";
      })
      .map((key) => ({
        key,
        name: window.cardano[key].name || key,
        icon: window.cardano[key].icon || null,
        apiVersion: window.cardano[key].apiVersion || null,
      }));
  }

  /** Calls enable() on the chosen wallet, returning its CIP-30 API object. */
  async function connect(walletKey) {
    const provider = window.cardano && window.cardano[walletKey];
    if (!provider) throw new Error("wallet: no provider registered as window.cardano." + walletKey);
    return provider.enable(); // may reject/throw if the user declines the connection prompt
  }

  /**
   * Pick an address to sign with. The design doc's protocol decision:
   * "stake address is the recommended default signing key but not
   * mandated" — so prefer a reward (stake) address, and fall back to a
   * payment address if the wallet doesn't expose one (e.g. it isn't
   * delegating, or the connected account has no stake key registered).
   * Returns hex, exactly as CIP-30's Address type is defined.
   */
  async function pickSigningAddress(api) {
    try {
      const rewardAddrs = await api.getRewardAddresses();
      if (Array.isArray(rewardAddrs) && rewardAddrs.length > 0) {
        return { addressHex: rewardAddrs[0], kind: "reward" };
      }
    } catch (e) {
      // Some wallets throw rather than return [] when there's no stake key.
      // Not fatal — fall through to a payment address.
    }
    const used = await api.getUsedAddresses();
    if (Array.isArray(used) && used.length > 0) {
      return { addressHex: used[0], kind: "used" };
    }
    const unused = await api.getUnusedAddresses();
    if (Array.isArray(unused) && unused.length > 0) {
      return { addressHex: unused[0], kind: "unused" };
    }
    throw new Error("wallet: no reward, used, or unused address was returned");
  }

  /**
   * Ask the wallet to sign `payloadBytes` with `addressHex`.
   * Returns the two hex strings the verification pipeline needs.
   *
   * CIP-30's `Bytes` type for signData's payload is a hex encoding of the
   * RAW message bytes (not CBOR-wrapped) — the wallet does the CIP-8/COSE
   * wrapping internally and hands back CBOR-encoded COSE structures in
   * the response.
   */
  async function signPayload(api, addressHex, payloadBytes) {
    const payloadHex = cbor.toHex(payloadBytes);
    const dataSignature = await api.signData(addressHex, payloadHex);
    if (!dataSignature || !dataSignature.signature || !dataSignature.key) {
      throw new Error("wallet: signData() returned an unexpected shape: " + JSON.stringify(dataSignature));
    }
    return { sign1Hex: dataSignature.signature, keyHex: dataSignature.key };
  }

  return { detectWallets, connect, pickSigningAddress, signPayload };
});
