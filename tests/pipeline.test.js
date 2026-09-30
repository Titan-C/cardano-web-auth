const cbor = require('../cbor.js');
const cose = require('../cose.js');
const AuthProtocol = require('../protocol.js');
const MockBackend = require('../mock-backend.js');

let failures = 0;
function check(cond, msg) {
  if (cond) console.log('ok:', msg);
  else { console.error('FAIL:', msg); failures++; }
}

// Simulates what a real CIP-30 wallet's `signData(address, payload)` does:
// builds protected/unprotected headers, computes Sig_structure, signs it.
async function walletSign(privateKey, addressBytes, payloadBytes, { hashed = false } = {}) {
  const protectedBytes = cose.encodeProtectedHeader({ addressBytes });
  const unprotectedMap = cose.encodeUnprotectedHeader({ hashed });
  const sigStructure = cose.buildSigStructure(protectedBytes, payloadBytes);
  const signature = new Uint8Array(await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, sigStructure));
  const sign1Array = [protectedBytes, unprotectedMap, payloadBytes, signature];
  return cbor.toHex(cbor.encode(sign1Array));
}

function coseKeyHexFor(rawPub) {
  return cbor.toHex(cbor.encode(new Map([[1, 1], [-1, 6], [3, -8], [-2, rawPub]])));
}

(async () => {
  const origin = 'https://arsmagna.xyz';
  const backend = MockBackend.createBackend(() => origin);

  const kp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const keyHex = coseKeyHexFor(rawPub);
  const addressBytes = new Uint8Array(29).fill(0x61); // dummy "address"
  const addressHex = cbor.toHex(addressBytes);

  // ---------- 1. SIGNUP: happy path ----------
  {
    const { nonce } = backend.requestNonce({ addressHex, action: 'signup' });
    const { bytes } = AuthProtocol.buildPayload({ uri: origin, nonce, action: 'signup', timestamp: Date.now() });
    const sign1Hex = await walletSign(kp.privateKey, addressBytes, bytes);
    const result = await backend.verify({ sign1Hex, keyHex });
    check(result.ok, 'signup succeeds');
    check(result.stages.every(s => s.ok), 'signup: every stage passed');
    check(!!result.sessionToken, 'signup creates a session token');
    check(!!backend.findAccountByAddressHex(addressHex), 'signup creates an account');
  }

  // ---------- 2. SIGNUP AGAIN: must fail at 'address' stage ----------
  {
    const { nonce } = backend.requestNonce({ addressHex, action: 'signup' });
    const { bytes } = AuthProtocol.buildPayload({ uri: origin, nonce, action: 'signup', timestamp: Date.now() });
    const sign1Hex = await walletSign(kp.privateKey, addressBytes, bytes);
    const result = await backend.verify({ sign1Hex, keyHex });
    check(!result.ok, 'double signup is rejected');
    check(result.stages.find(s => s.name === 'address').ok === false, 'double signup fails at address stage');
  }

  // ---------- 3. LOGIN: happy path ----------
  let loginSessionToken;
  {
    const { nonce } = backend.requestNonce({ addressHex, action: 'login' });
    const { bytes } = AuthProtocol.buildPayload({ uri: origin, nonce, action: 'login', timestamp: Date.now() });
    const sign1Hex = await walletSign(kp.privateKey, addressBytes, bytes);
    const result = await backend.verify({ sign1Hex, keyHex });
    check(result.ok, 'login succeeds');
    loginSessionToken = result.sessionToken;
    check(!!backend.getSession(loginSessionToken), 'login session is retrievable');
  }

  // ---------- 4. LOGIN for unknown address: must fail at 'address' stage ----------
  {
    const otherKp = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify']);
    const otherPub = new Uint8Array(await crypto.subtle.exportKey('raw', otherKp.publicKey));
    const otherKeyHex = coseKeyHexFor(otherPub);
    const otherAddrBytes = new Uint8Array(29).fill(0x62);
    const otherAddrHex = cbor.toHex(otherAddrBytes);
    const { nonce } = backend.requestNonce({ addressHex: otherAddrHex, action: 'login' });
    const { bytes } = AuthProtocol.buildPayload({ uri: origin, nonce, action: 'login', timestamp: Date.now() });
    const sign1Hex = await walletSign(otherKp.privateKey, otherAddrBytes, bytes);
    const result = await backend.verify({ sign1Hex, keyHex: otherKeyHex });
    check(!result.ok, 'login with no account is rejected');
    check(result.stages.find(s => s.name === 'address').ok === false, 'unknown-account login fails at address stage');
  }

  // ---------- 5. STEP-UP (prove-ownership): happy path, no new session ----------
  {
    const { nonce } = backend.requestNonce({ addressHex, action: 'prove-ownership' });
    const { bytes } = AuthProtocol.buildPayload({ uri: origin, nonce, action: 'prove-ownership', timestamp: Date.now() });
    const sign1Hex = await walletSign(kp.privateKey, addressBytes, bytes);
    const result = await backend.verify({ sign1Hex, keyHex });
    check(result.ok, 'step-up succeeds');
    check(result.sessionToken === undefined, 'step-up does not mint a new session token');
  }

  // ---------- 6. REPLAY: reusing a consumed nonce must fail at 'nonce' stage ----------
  {
    const { nonce } = backend.requestNonce({ addressHex, action: 'login' });
    const { bytes } = AuthProtocol.buildPayload({ uri: origin, nonce, action: 'login', timestamp: Date.now() });
    const sign1Hex = await walletSign(kp.privateKey, addressBytes, bytes);
    const first = await backend.verify({ sign1Hex, keyHex });
    check(first.ok, 'first use of nonce succeeds');
    const replay = await backend.verify({ sign1Hex, keyHex });
    check(!replay.ok, 'replaying the same signed message is rejected');
    check(replay.stages.find(s => s.name === 'nonce').ok === false, 'replay fails at nonce stage');
  }

  // ---------- 7. MISMATCHED ORIGIN: malicious payload.uri must fail at 'uri' stage ----------
  {
    // The nonce is (honestly) bound to the real origin by the backend...
    const { nonce } = backend.requestNonce({ addressHex, action: 'login' });
    // ...but a malicious/buggy frontend builds a payload claiming a
    // DIFFERENT uri. A real wallet will still sign it — CIP-8 doesn't
    // stop a dApp from lying about its own origin inside the payload,
    // which is exactly the gap CIP-93's structured-payload + server-side
    // origin binding is meant to close.
    const { bytes } = AuthProtocol.buildPayload({ uri: 'https://not-this-site.example', nonce, action: 'login', timestamp: Date.now() });
    const sign1Hex = await walletSign(kp.privateKey, addressBytes, bytes);
    const result = await backend.verify({ sign1Hex, keyHex });
    check(!result.ok, 'mismatched-origin payload is rejected');
    check(result.stages.find(s => s.name === 'uri').ok === false, 'mismatched origin fails at uri stage specifically');
    check(result.stages.filter(s => s.ok).map(s => s.name).join(',') === 'parse,address,nonce,timestamp', 'stages before uri all passed (demonstrates fail-fast + specific diagnosis)');
  }

  // ---------- 8. WRONG ACTION: payload action != nonce's committed action ----------
  {
    const { nonce } = backend.requestNonce({ addressHex, action: 'login' });
    // attacker/bug tries to reuse a login nonce to authorize a step-up instead
    const { bytes } = AuthProtocol.buildPayload({ uri: origin, nonce, action: 'prove-ownership', timestamp: Date.now() });
    const sign1Hex = await walletSign(kp.privateKey, addressBytes, bytes);
    const result = await backend.verify({ sign1Hex, keyHex });
    check(!result.ok, 'action-swapped payload is rejected');
    check(result.stages.find(s => s.name === 'action').ok === false, 'action swap fails at action stage');
  }

  // ---------- 9. EXPIRED NONCE: must fail at 'timestamp' stage ----------
  {
    const { nonce } = backend.requestNonce({ addressHex, action: 'login' });
    backend._inspect.nonces.get(nonce).issuedAt = Date.now() - (AuthProtocol.NONCE_TTL_MS + 60000); // force expiry
    const { bytes } = AuthProtocol.buildPayload({ uri: origin, nonce, action: 'login', timestamp: Date.now() });
    const sign1Hex = await walletSign(kp.privateKey, addressBytes, bytes);
    const result = await backend.verify({ sign1Hex, keyHex });
    check(!result.ok, 'expired nonce is rejected');
    check(result.stages.find(s => s.name === 'timestamp').ok === false, 'expired nonce fails at timestamp stage');
  }

  // ---------- 10. hashed=true payload: must fail cleanly at 'signature' stage ----------
  {
    const { nonce } = backend.requestNonce({ addressHex, action: 'login' });
    const { bytes } = AuthProtocol.buildPayload({ uri: origin, nonce, action: 'login', timestamp: Date.now() });
    const sign1Hex = await walletSign(kp.privateKey, addressBytes, bytes, { hashed: true });
    const result = await backend.verify({ sign1Hex, keyHex });
    check(!result.ok, 'hashed=true payload is rejected (out of scope, not silently mishandled)');
    check(result.stages.find(s => s.name === 'signature').ok === false, 'hashed payload fails specifically at signature stage');
  }

  console.log(failures === 0 ? '\nALL PIPELINE TESTS PASSED' : '\n' + failures + ' TEST(S) FAILED');
  process.exitCode = failures === 0 ? 0 : 1;
})().catch(e => { console.error('ERROR', e); process.exitCode = 1; });
