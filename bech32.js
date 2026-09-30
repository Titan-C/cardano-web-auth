/**
 * bech32.js — BIP-173 bech32 encode/decode, plus a small Cardano-specific
 * helper to turn raw address bytes into the familiar addr1.../stake1...
 * form.
 *
 * COSMETIC ONLY. Every piece of protocol logic in this demo (nonce
 * binding, address matching, the whole verification pipeline) operates
 * on raw hex bytes, exactly as CIP-30 hands them over — never on a
 * bech32 string. This file exists purely so the UI can show addresses in
 * a form people actually recognize instead of a wall of hex. If you
 * delete this file, the auth flow itself is unaffected; only the address
 * display gets uglier.
 *
 * Reference: BIP-173, https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
 * (Cardano addresses use plain bech32, not bech32m.)
 */
(function (root, factory) {
  if (typeof module !== "undefined" && module.exports) {
    module.exports = factory();
  } else {
    root.Bech32 = factory();
  }
})(typeof window !== "undefined" ? window : globalThis, function () {
  "use strict";

  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

  function polymod(values) {
    let chk = 1;
    for (const v of values) {
      const top = chk >>> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) {
        if ((top >>> i) & 1) chk ^= GENERATOR[i];
      }
    }
    return chk >>> 0;
  }

  function hrpExpand(hrp) {
    const out = [];
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >>> 5);
    out.push(0);
    for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
    return out;
  }

  function createChecksum(hrp, data) {
    const values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    const mod = polymod(values) ^ 1;
    const ret = [];
    for (let i = 0; i < 6; i++) ret.push((mod >>> (5 * (5 - i))) & 31);
    return ret;
  }

  function verifyChecksum(hrp, data) {
    return polymod(hrpExpand(hrp).concat(data)) === 1;
  }

  /** Regroup an array of `fromBits`-bit values into `toBits`-bit values. */
  function convertBits(data, fromBits, toBits, pad) {
    let acc = 0;
    let bits = 0;
    const ret = [];
    const maxv = (1 << toBits) - 1;
    for (const value of data) {
      if (value < 0 || value >> fromBits !== 0) throw new Error("bech32: invalid value for convertBits");
      acc = (acc << fromBits) | value;
      bits += fromBits;
      while (bits >= toBits) {
        bits -= toBits;
        ret.push((acc >>> bits) & maxv);
      }
    }
    if (pad) {
      if (bits > 0) ret.push((acc << (toBits - bits)) & maxv);
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
      throw new Error("bech32: invalid padding in convertBits");
    }
    return ret;
  }

  function encode(hrp, bytes) {
    const data5 = convertBits(Array.from(bytes), 8, 5, true);
    const checksum = createChecksum(hrp, data5);
    const combined = data5.concat(checksum);
    let out = hrp + "1";
    for (const d of combined) out += CHARSET[d];
    return out;
  }

  function decode(str) {
    if (str.toLowerCase() !== str && str.toUpperCase() !== str) {
      throw new Error("bech32: mixed case is not allowed");
    }
    if (str.length < 8 || str.length > 90) throw new Error("bech32: length out of range");
    const s = str.toLowerCase();
    const pos = s.lastIndexOf("1");
    if (pos < 1 || pos + 7 > s.length) throw new Error("bech32: no valid separator");
    const hrp = s.slice(0, pos);
    for (let i = 0; i < hrp.length; i++) {
      const code = hrp.charCodeAt(i);
      if (code < 33 || code > 126) throw new Error("bech32: HRP character out of range [33,126]");
    }
    const dataChars = s.slice(pos + 1);
    const data = [];
    for (const ch of dataChars) {
      const v = CHARSET.indexOf(ch);
      if (v === -1) throw new Error("bech32: invalid character " + ch);
      data.push(v);
    }
    if (!verifyChecksum(hrp, data)) throw new Error("bech32: invalid checksum");
    const payload = data.slice(0, data.length - 6);
    return { hrp, bytes: new Uint8Array(convertBits(payload, 5, 8, false)) };
  }

  // ---- Cardano-specific helper (CIP-19 address header layout) --------

  /**
   * Turn raw Cardano address bytes into their bech32 form, purely for
   * display. Returns null (rather than throwing) for anything this
   * helper doesn't recognize — e.g. Byron addresses, which use base58
   * rather than bech32 and are out of scope here — so callers can fall
   * back to showing hex.
   */
  function cardanoAddressToBech32(bytes) {
    if (!bytes || bytes.length === 0) return null;
    const header = bytes[0];
    const type = (header >> 4) & 0x0f;
    const networkTag = header & 0x0f;
    if (type === 8) return null; // Byron — base58, not bech32; out of scope
    const isReward = type === 14 || type === 15;
    const base = isReward ? "stake" : "addr";
    const hrp = networkTag === 1 ? base : base + "_test";
    try {
      return encode(hrp, bytes);
    } catch (e) {
      return null;
    }
  }

  return { encode, decode, cardanoAddressToBech32 };
});
