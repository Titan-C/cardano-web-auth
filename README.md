# Wallet-native authentication — JS demo

A runnable, didactic implementation of the authentication flow: signing in to a
web app with a Cardano wallet (CIP-8 message signing + CIP-30 wallet bridge)
instead of a password, using a CIP-93-style structured JSON payload so the
backend can bind each signature to a specific action, origin, and single-use
nonce.

This is a **demo and developer reference** a vanilla-JS version you can open in
a browser today, with the "backend" simulated client-side (see [Why a mock
backend](#why-a-mock-backend) below). Treat it as a working preview of the
protocol.

## Try it

Open `index.html` in a browser with a CIP-30 wallet extension installed. No
build step, no `npm install`, no server — plain `<script>` tags, and Tailwind's
CDN build for styling.

1. **Connect a wallet.**
2. **Sign up.** Your wallet will prompt you to sign a small JSON message
   (visible in the "What you're about to sign" panel before you approve
   it). The pipeline log on the right shows all six verification stages
   passing.
3. **Log in.** Same idea, a fresh nonce each time.
4. **Try the "wrong" one on purpose.** Sign up again with the same address,
   or log in before ever signing up. Both buttons are always clickable —
   the demo deliberately doesn't pre-check which one applies and disable
   the other, because that check *is* the `address` pipeline stage: a
   duplicate signup or an account-less login gets rejected live, in the
   log, based on the signed message itself. Hiding that behind a
   pre-flight check would defeat the point of watching it happen.
5. ***Prove ownership.** Available once you're signed in — this is the "prove
   it's still you" re-authentication for a sensitive action or proving ownership
   of specific assets inside an address you control.
6. **Demo scenarios** — do these *after* signing up, so the account exists
   and the failure you see is the one the button names, not an earlier
   "no account" rejection:
   - **Attempt login with a forged origin** — builds a real, validly-signed
     message whose `uri` field doesn't match this page's real origin, and
     shows the backend rejecting it specifically at the `uri` stage.
   - **Replay the last signed message** — resubmits the exact same signed
     bytes without asking the wallet to sign again, and shows the backend
     rejecting it at the `nonce` stage (single-use nonces stop replay).

**Disconnect** (in the wallet panel) drops the connection and ends the
current session, so you can connect a different wallet or address and try
the whole flow again from a clean state.

No real wallet handy? The whole crypto/verification pipeline is exercised
without a browser or a wallet in `tests/pipeline.test.js` — see
[Testing](#testing).

## File boundaries — what's generic vs. protocol-specific

The design doc asks for "clear boundaries between generic CIP-30/CIP-93
plumbing and protocol-specific logic, so someone reading the reference
implementation can see what to copy and what to replace." That's the whole
reason this is six small files instead of one big one:

| File | What it is |
|---|---|
| `cbor.js` | Generic CBOR codec — just enough of RFC 8949 for COSE structures. Knows nothing about wallets or Cardano. |
| `cose.js` | Generic CIP-8/COSE handling — decode COSE_Sign1/COSE_Key, build the Sig_structure, verify Ed25519. Reusable for *any* CIP-8 signing use case. |
| `bech32.js` | Generic BIP-173 bech32 codec, plus a Cardano-address-header helper. **Display only** — see below. |
| `wallet.js` | Generic CIP-30 plumbing — wallet detection, `enable()`, address selection, `signData()`. Would look the same for a different signing feature. |
| `protocol.js` | **Protocol-specific.** The structured payload shape and the six-stage verification pipeline. This is the part that's actually about *this* auth scheme. |
| `mock-backend.js` | **Protocol-specific**, and demo-only — nonce/account/session state, shaped to mirror the real backend's future API surface (see below). |
| `app.js` | UI wiring. No protocol logic of its own. |

If you're lifting this into the real backend: copy `cbor.js`/`cose.js` close to
as-is, keep `wallet.js`/`app.js`'s *shape* as a reference for the frontend, and
treat `protocol.js` as the pipeline to re-implement server-side —
`mock-backend.js` is deliberately written so each function's body is what a real
route handler would do, minus the HTTP framing:

| Mock function | Real endpoint (per the design doc's API surface draft) |
|---|---|
| `requestNonce({ addressHex, action })` | `POST /auth/nonce` |
| `verify({ sign1Hex, keyHex })` | `POST /auth/verify` |
| `getSession(token)` | `GET /auth/session` |

## The six-stage pipeline

In the exact order fixed by the M1 spec: **parse COSE → address → nonce →
timestamp → uri → action → signature.** `protocol.js` has a long comment on
*why* the expensive cryptographic check (signature) runs last rather than
first — short version: every earlier stage is a cheap check against a
*claim* the request makes, so ordering them first means a bad request fails
fast and the demo can say exactly which claim was wrong, instead of one
opaque "invalid signature" covering every possible failure. Nothing is
treated as authenticated until every stage — signature included — passes.

**Payload shape**:

```json
{ "uri": "https://arsmagna.xyz", "nonce": "9f2a…", "action": "login", "timestamp": 1234567890123 }
```

## Known limitations (deliberate, not oversights)

- **`hashed: true` payloads aren't supported.** CIP-8 allows signing a
  Blake2b-224 hash of the payload instead of the payload itself (for
  hardware-wallet-sized messages). Implementing Blake2b by hand without
  test vectors from a real device felt like exactly the kind of
  security-sensitive code the design doc warns against hand-waving, so
  this demo detects `hashed: true` and reports it clearly (pipeline fails
  at the `signature` stage with an explicit reason) rather than guessing.
- **No address ↔ public-key derivation check.** A Shelley address embeds a
  Blake2b-224 hash of its payment/stake key. A fuller implementation would
  recompute that hash from the COSE_Key's public key and confirm it matches
  the address in the protected header. This demo doesn't — same reasoning
  as above — and instead relies on comparing the address bytes at the
  `address`/`nonce` stages, which is what CIP-8 requires but doesn't harden
  against a forged COSE_Key paired with someone else's address bytes. Note
  this before treating the demo's `address` stage as sufficient on its own.
- **Ed25519 verification uses the browser's native Web Crypto
  (`SubtleCrypto`, "Secure Curves" API)** rather than a bundled JS
  implementation. This is a deliberate trade-off in the other direction —
  it means relying on the platform's audited implementation instead of
  hand-rolled elliptic-curve code, at the cost of needing a browser new
  enough to support it (current Chrome, Firefox, and Safari all do).
- **The "wallet doesn't recognize the structured payload" fallback** is
  real wallet UI behavior this demo can't control or fake — try the same
  flow with different installed wallets to see it for yourself.
- **Sessions and nonces are in-memory** and vanish on page reload. Fine for
  a demo; the design doc already flags this as a "call out clearly, fix in
  production" item.

## Testing

`cbor.js`, `cose.js`, `bech32.js`, `protocol.js`, and `mock-backend.js` are
plain functions with no DOM dependency, so they're unit-tested under Node
rather than only by hand in a browser:

```sh
node tests/cbor.test.js       # CBOR round-trips + malformed-input rejection
node tests/cose.test.js       # build/sign/decode/verify a real Ed25519 signature; tamper + wrong-key negatives
node tests/bech32.test.js     # official BIP-173 test vectors + Cardano address-header cases
node tests/pipeline.test.js   # all 6 pipeline stages, against a real (test-generated) Ed25519 keypair:
                               #   signup, login, step-up, double-signup, unknown-account login,
                               #   replay, forged origin, action-swap, expired nonce, hashed payload
```

`wallet.js` and `app.js` are the only two files that touch the DOM /
`window.cardano`, so they're the only parts that still need a real browser
and a real wallet extension to exercise — everything they call has already
been verified against real (test-generated) signatures by the suite above.

## Styling

Tailwind CSS via the CDN build (`https://cdn.tailwindcss.com`), default
theme only — no custom colors, no arbitrary values, no separate stylesheet.
Loading Tailwind this way means the page needs network access to render
correctly (it's the one thing here that isn't fully offline); swap in a
built Tailwind stylesheet if you fold this into arsmagna.xyz's own build.
