/**
 * app.js — UI wiring only. Every actual protocol/crypto decision lives in
 * protocol.js, cose.js, cbor.js, wallet.js, and mock-backend.js; this file
 * just calls them in response to clicks and renders what came back.
 *
 * Dynamically created elements use the same Tailwind utility classes as
 * index.html (no custom CSS anywhere) so the page has one consistent
 * styling approach throughout.
 *
 * UI STATES (see refreshUI()): the four sections in the left column are
 * mutually exclusive by design, not just collapsible —
 *   - wallet not connected: only the wallet picker shows
 *   - connected, signed out: wallet summary + "sign up or log in" show
 *   - connected, signed in: wallet summary + "signed in" actions show
 * "Demo scenarios" is the one exception: it's available any time a wallet
 * is connected, signed in or not, since the scenarios themselves exercise
 * the login flow.
 */
(function () {
  "use strict";

  const STAGE_ORDER = [
    "parse",
    "address",
    "nonce",
    "timestamp",
    "uri",
    "action",
    "signature",
  ];
  const STAGE_LABEL = {
    parse: "Parse COSE",
    address: "Address",
    nonce: "Nonce",
    timestamp: "Timestamp",
    uri: "URI (domain binding)",
    action: "Action",
    signature: "Signature",
  };

  const backend = MockBackend.createBackend(() => window.location.origin);

  const state = {
    api: null,
    addressHex: null,
    addressKind: null,
    walletName: null,
    sessionToken: null,
    sessionSince: null,
    lastSign1Hex: null,
    lastKeyHex: null,
  };

  // ---- element refs -----------------------------------------------------
  const el = {
    walletPicker: document.getElementById("wallet-picker"),
    walletList: document.getElementById("wallet-list"),
    walletConnected: document.getElementById("wallet-connected"),
    connectedWalletName: document.getElementById("connected-wallet-name"),
    connectedAddress: document.getElementById("connected-address"),
    btnDisconnect: document.getElementById("btn-disconnect"),

    stepAccount: document.getElementById("step-account"),
    accountHint: document.getElementById("account-hint"),
    btnSignup: document.getElementById("btn-signup"),
    btnLogin: document.getElementById("btn-login"),

    stepSession: document.getElementById("step-session"),
    sessionAddress: document.getElementById("session-address"),
    sessionSince: document.getElementById("session-since"),
    btnConfirm: document.getElementById("btn-confirm"),
    btnLogout: document.getElementById("btn-logout"),

    stepScenarios: document.getElementById("step-scenarios"),
    btnMismatchedOrigin: document.getElementById("btn-mismatched-origin"),
    btnReplay: document.getElementById("btn-replay"),

    payloadPreview: document.getElementById("payload-preview"),
    payloadPreviewNote: document.getElementById("payload-preview-note"),
    payloadPreviewJson: document.getElementById("payload-preview-json"),

    logList: document.getElementById("log-list"),
  };

  // ---- wallet picker ------------------------------------------------
  function renderWalletList() {
    const wallets = CipWallet.detectWallets();
    el.walletList.innerHTML = "";
    if (wallets.length === 0) {
      const p = document.createElement("p");
      p.className = "text-gray-500";
      p.textContent =
        "No CIP-30 wallet detected. Install a wallet extension (Eternl, Nami, Flint, Yoroi, Lace, …) and reload this page.";
      el.walletList.appendChild(p);
      return;
    }
    for (const w of wallets) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className =
        "rounded-md border border-gray-300 px-4 py-2 font-medium hover:bg-gray-50 hover:shadow flex flex-col items-center";
      const img = document.createElement("img");
      img.className = "h-12 w-12 object-contain";
      img.src = w.icon;
      btn.appendChild(img);
      btn.appendChild(document.createTextNode(w.name));
      btn.addEventListener("click", () => connectWallet(w));
      el.walletList.appendChild(btn);
    }
  }

  async function connectWallet(walletEntry) {
    try {
      const api = await CipWallet.connect(walletEntry.key);
      const picked = await CipWallet.pickSigningAddress(api);
      state.api = api;
      state.addressHex = picked.addressHex;
      state.addressKind = picked.kind;
      state.walletName = walletEntry.name;
      refreshUI();
    } catch (e) {
      alert("Couldn't connect that wallet: " + e.message);
    }
  }

  /**
   * Disconnecting also ends any active session. CIP-30 has no notion of a
   * dApp-initiated "disable" — a real dApp just forgets its reference to
   * the API object, which is all this does too. Ending the session at the
   * same time is a demo simplification: it avoids a "signed in, but no
   * wallet connected to prove it" limbo state, which has no equivalent
   * signer to do anything useful (like step-up) with anyway.
   */
  function disconnectWallet() {
    if (state.sessionToken) backend.endSession(state.sessionToken);
    state.api = null;
    state.addressHex = null;
    state.addressKind = null;
    state.walletName = null;
    state.sessionToken = null;
    state.sessionSince = null;
    state.lastSign1Hex = null;
    state.lastKeyHex = null;
    el.btnReplay.disabled = true;
    el.payloadPreview.hidden = true;
    refreshUI();
  }

  // ---- central UI state --------------------------------------------------
  function refreshUI() {
    const connected = !!state.api;
    el.walletPicker.hidden = connected;
    el.walletConnected.hidden = !connected;
    el.walletConnected.classList.toggle("flex", connected);
    el.stepScenarios.hidden = !connected;

    if (!connected) {
      el.stepAccount.hidden = true;
      el.stepSession.hidden = true;
      return;
    }

    const addressBytes = CborCodec.fromHex(state.addressHex);
    const bech32Form = Bech32.cardanoAddressToBech32(addressBytes);
    el.connectedWalletName.textContent = state.walletName;
    el.connectedAddress.textContent = bech32Form || state.addressHex;
    el.connectedAddress.title = state.addressHex;

    const signedIn = !!(
      state.sessionToken && backend.getSession(state.sessionToken)
    );

    el.stepAccount.hidden = signedIn;
    el.stepSession.hidden = !signedIn;

    if (signedIn) {
      el.sessionAddress.textContent = bech32Form || state.addressHex;
      el.sessionSince.textContent =
        "Since " + new Date(state.sessionSince).toLocaleTimeString();
    } else {
      // Deliberately NOT pre-checking whether this address already has an
      // account and disabling one of the two buttons accordingly. That
      // check is exactly what the pipeline's "address" stage demonstrates:
      // a duplicate signup, or a login with no account, gets rejected
      // based on the signed message itself, live, in the log on the
      // right. Hiding that behind a pre-flight check would defeat the
      // point — same as a real website, you don't know in advance
      // whether you have an account; you try one and the response tells
      // you. (The mock backend *could* answer "does this address have an
      // account?" cheaply since it's a same-page mock — but a real
      // backend wouldn't expose that pre-check either, so neither does
      // this demo.)
      el.btnSignup.disabled = false;
      el.btnLogin.disabled = false;
      el.accountHint.textContent =
        "New here? Sign up. Already have an account for this address? Log in. Picked the wrong one? The pipeline on the right will show you exactly why it was rejected.";
    }
  }

  // ---- payload preview -----------------------------------------------
  function showPayloadPreview(payloadObj, note) {
    el.payloadPreview.hidden = false;
    el.payloadPreviewJson.textContent = JSON.stringify(payloadObj, null, 2);
    if (note) {
      el.payloadPreviewNote.hidden = false;
      el.payloadPreviewNote.textContent = note;
    } else {
      el.payloadPreviewNote.hidden = true;
      el.payloadPreviewNote.textContent = "";
    }
  }

  // ---- core flow: request nonce, sign, verify -------------------------
  async function runFlow(action, { forgedUri, label } = {}) {
    if (!state.api || !state.addressHex) return;
    let nonceInfo;
    try {
      nonceInfo = backend.requestNonce({
        addressHex: state.addressHex,
        action,
      });
    } catch (e) {
      appendLogEntry({
        title: label || action,
        ok: false,
        stages: [
          {
            name: "parse",
            ok: false,
            detail: "nonce request failed: " + e.message,
          },
        ],
      });
      return;
    }

    const uri = forgedUri || nonceInfo.uri;
    const { obj: payloadObj, bytes: payloadBytes } = AuthProtocol.buildPayload({
      uri,
      nonce: nonceInfo.nonce,
      action,
      timestamp: Date.now(),
    });

    showPayloadPreview(
      payloadObj,
      forgedUri
        ? "⚠ This uri is deliberately wrong — it does not match this page's real origin. Your wallet will still sign it; the backend should reject it."
        : null,
    );

    let sign1Hex, keyHex;
    try {
      const signed = await CipWallet.signPayload(
        state.api,
        state.addressHex,
        payloadBytes,
      );
      sign1Hex = signed.sign1Hex;
      keyHex = signed.keyHex;
    } catch (e) {
      appendLogEntry({
        title: label || action,
        ok: false,
        stages: [
          {
            name: "parse",
            ok: false,
            detail: "wallet did not return a signature: " + e.message,
          },
        ],
      });
      return;
    }

    state.lastSign1Hex = sign1Hex;
    state.lastKeyHex = keyHex;
    el.btnReplay.disabled = false;

    const result = await backend.verify({ sign1Hex, keyHex });
    if (result.ok && result.sessionToken) {
      state.sessionToken = result.sessionToken;
      state.sessionSince = Date.now();
    }
    refreshUI();
    appendLogEntry({
      title: label || action,
      ok: result.ok,
      stages: result.stages,
    });
  }

  async function runReplay() {
    if (!state.lastSign1Hex || !state.lastKeyHex) return;
    const result = await backend.verify({
      sign1Hex: state.lastSign1Hex,
      keyHex: state.lastKeyHex,
    });
    appendLogEntry({
      title: "Replay the last signed message",
      ok: result.ok,
      stages: result.stages,
    });
  }

  function logout() {
    if (state.sessionToken) backend.endSession(state.sessionToken);
    state.sessionToken = null;
    state.sessionSince = null;
    refreshUI();
  }

  // ---- verification log rendering --------------------------------------
  function appendLogEntry({ title, ok, stages }) {
    if (
      el.logList.firstElementChild &&
      el.logList.firstElementChild.tagName === "P"
    ) {
      el.logList.innerHTML = ""; // clear the "nothing signed yet" placeholder
    }

    const card = document.createElement("article");
    card.className = "border border-gray-200 rounded-lg p-4";

    const header = document.createElement("div");
    header.className = "flex items-center justify-between gap-3";

    const titleEl = document.createElement("h3");
    titleEl.className = "font-semibold";
    titleEl.textContent = title;

    const badge = document.createElement("span");
    badge.className =
      "text-xs font-semibold px-2 py-1 rounded-full " +
      (ok ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800");
    badge.textContent = ok ? "VERIFIED" : "REJECTED";

    header.appendChild(titleEl);
    header.appendChild(badge);
    card.appendChild(header);

    const time = document.createElement("p");
    time.className = "text-xs text-gray-400 mt-0.5";
    time.textContent = new Date().toLocaleTimeString();
    card.appendChild(time);

    const list = document.createElement("ol");
    list.className = "mt-3 flex flex-col gap-1.5 text-sm";

    const byName = new Map(stages.map((s) => [s.name, s]));
    for (const name of STAGE_ORDER) {
      const s = byName.get(name);
      const row = document.createElement("li");
      row.className = "flex items-start gap-2";

      const icon = document.createElement("span");
      icon.className = "mt-0.5 shrink-0";
      icon.textContent = !s ? "–" : s.ok ? "✅" : "❌";
      if (!s) icon.className += " text-gray-300";

      const text = document.createElement("span");
      text.className = !s
        ? "text-gray-300"
        : s.ok
          ? "text-gray-700"
          : "text-red-700";
      const label = document.createElement("span");
      label.className = "font-medium";
      label.textContent = STAGE_LABEL[name];
      text.appendChild(label);
      if (s && s.detail) {
        text.appendChild(document.createTextNode(" — " + s.detail));
      } else if (!s) {
        text.appendChild(document.createTextNode(" — not reached"));
      }

      row.appendChild(icon);
      row.appendChild(text);
      list.appendChild(row);
    }
    card.appendChild(list);

    el.logList.insertBefore(card, el.logList.firstChild);
  }

  // ---- wire up buttons --------------------------------------------------
  el.btnDisconnect.addEventListener("click", disconnectWallet);
  el.btnSignup.addEventListener("click", () =>
    runFlow("signup", { label: "Sign up" }),
  );
  el.btnLogin.addEventListener("click", () =>
    runFlow("login", { label: "Log in" }),
  );
  el.btnConfirm.addEventListener("click", () =>
    runFlow("prove-ownership", { label: "Prove ownership" }),
  );
  el.btnLogout.addEventListener("click", logout);
  el.btnMismatchedOrigin.addEventListener("click", () =>
    runFlow("login", {
      forgedUri: "https://not-" + window.location.hostname,
      label: "⚠ Login with a forged origin",
    }),
  );
  el.btnReplay.addEventListener("click", runReplay);
  refreshUI();
  // Wallet extensions can inject window.cardano slightly after page load;
  // a short delayed re-scan catches wallets that weren't there on the first pass.
  setTimeout(renderWalletList, 800);
})();
