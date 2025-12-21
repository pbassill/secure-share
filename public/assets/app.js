'use strict';

/*
  Secure Share SPA (single-file app.js)

  Security model:
  - End-to-end encryption in the browser using AES-256-GCM via WebCrypto.
  - The server stores ciphertext only (manifest.bin + encrypted chunk files).
  - The retrieval code is carried in the URL fragment (#...), which is not sent to the server.
  - The code contains: locator (24 bytes), AES key seed (32 bytes), delete seed (32 bytes), salt (16 bytes), and a random baseNonce8 (8 bytes) used for GCM nonces.
  - Chunk nonces are derived as baseNonce8 || uint32be(chunkIndex). Manifest uses baseNonce8 || 0xFFFFFFFF.
  - AAD binds version, locator, kind (chunk/manifest), and index into the authentication tag, preventing server-side tampering.

  Backend endpoints expected (as per earlier pack):
  - GET  /api/pow/challenge                       (Tor/I2P only; optional)
  - POST /api/share/init                          { locator_hex, type, size_bytes, chunk_size, expires_at_epoch, delete_token_hash_b64u, network?, pow_*? }
  - PUT  /api/share/{locator_hex}/chunk/{i}       (Bearer upload_token)
  - PUT  /api/share/{locator_hex}/manifest        (Bearer upload_token)
  - POST /api/share/{locator_hex}/complete        (Bearer upload_token)
  - GET  /api/share/{locator_hex}/manifest
  - GET  /api/share/{locator_hex}/chunk/{i}
  - POST /api/share/{locator_hex}/delete          { delete_token_b64u }

  Optional auth endpoints (passkey-first WebAuthn scaffold):
  - GET  /api/auth/register/options
  - POST /api/auth/register/verify
  - GET  /api/auth/login/options
  - POST /api/auth/login/verify
  - POST /api/auth/logout

  Notes:
  - This file assumes the server enforces policy: anonymous <=100MB, <=2 uploads/hour, anon retention capped to 6 hours.
    Authenticated users may request retention up to 14 days and exceed size limits (once you wire that logic server-side).
*/

const APP = {
  VERSION: 1,

  // Default chunk size. Keep small for anonymous. You may tune for authenticated.
  CHUNK_SIZE_DEFAULT: 1024 * 1024, // 1 MiB

  // Code payload layout (bytes):
  // 0: version(1)
  // 1: flags(1)
  // 2..25: locator(24)
  // 26..41: salt(16)
  // 42..73: keyseed(32)
  // 74..105: delseed(32)
  // 106..159: reserved(54) (we use first 8 bytes for baseNonce8)
  CODE_PAYLOAD_LEN: 160,

  // Flags
  FLAG_FILE: 0x01,
  FLAG_PAS:  0x00,

  // Manifest index sentinel for AAD and nonce derivation
  MANIFEST_INDEX: 0xFFFFFFFF,

  // Max retention display (14 days = 336 hours)
  MAX_HOURS: 336,
  DEFAULT_HOURS: 6,
};

(function main() {
  boot().catch(err => {
    console.error(err);
    renderFatal(err);
  });
})();

/* -------------------------- UI -------------------------- */

function setApp(html) {
  const el = document.getElementById('app');
  if (el) el.innerHTML = html;
}

function renderFatal(err) {
  setApp(`
    <main style="max-width:860px;margin:2rem auto;font-family:system-ui;">
      <h1>Secure Share</h1>
      <p style="color:#b00;">Fatal error: ${escapeHtml(String(err?.message || err))}</p>
    </main>
  `);
}

function escapeHtml(s) {
  return s.replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

function renderHome(prefillCodeOrLink = '') {
  setApp(`
    <main style="max-width:860px;margin:2rem auto;font-family:system-ui;line-height:1.45;">
      <h1>Secure Share</h1>

      <section style="margin-top:1rem;padding:1rem;border:1px solid #ddd;border-radius:10px;">
        <h2 style="margin:0 0 0.5rem 0;">Account (optional)</h2>
        <p style="margin:0 0 0.75rem 0;">
          Passkey accounts allow higher limits and longer retention, without email.
        </p>
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap;">
          <button id="btnReg">Register passkey</button>
          <button id="btnLogin">Sign in with passkey</button>
          <button id="btnLogout">Sign out</button>
        </div>
        <pre id="authOut" style="margin-top:0.75rem;white-space:pre-wrap;"></pre>
      </section>

      <section style="margin-top:1rem;padding:1rem;border:1px solid #ddd;border-radius:10px;">
        <h2 style="margin:0 0 0.5rem 0;">Create a share</h2>

        <div style="display:flex;gap:1rem;flex-wrap:wrap;align-items:flex-start;">
          <div style="flex:1;min-width:280px;">
            <h3 style="margin:0.25rem 0;">File</h3>
            <input id="fileInput" type="file" />
          </div>

          <div style="flex:1;min-width:280px;">
            <h3 style="margin:0.25rem 0;">Paste (plain text)</h3>
            <textarea id="pasteInput" rows="6" style="width:100%;" placeholder="Paste text here (stored encrypted)"></textarea>
          </div>
        </div>

        <div style="margin-top:0.75rem;display:flex;gap:1rem;flex-wrap:wrap;align-items:center;">
          <label>Retention (hours):</label>
          <input id="hours" type="number" min="1" max="${APP.MAX_HOURS}" value="${APP.DEFAULT_HOURS}" style="width:7rem;" />
          <label>Chunk size:</label>
          <select id="chunkSize">
            <option value="${256*1024}">256 KB</option>
            <option value="${512*1024}">512 KB</option>
            <option value="${1024*1024}" selected>1 MB</option>
            <option value="${2*1024*1024}">2 MB</option>
            <option value="${4*1024*1024}">4 MB</option>
          </select>
          <button id="btnUploadFile">Encrypt and upload file</button>
          <button id="btnUploadPaste">Encrypt and upload paste</button>
        </div>

        <details style="margin-top:0.75rem;">
          <summary>Advanced</summary>
          <div style="margin-top:0.5rem;">
            <label><input type="checkbox" id="usePowAllAnon" /> Require proof-of-work even on clearnet (anonymous only)</label>
          </div>
          <div style="margin-top:0.5rem;">
            <label>Optional passphrase (shared out-of-band):</label>
            <input id="passphrase" type="password" style="width:100%;" placeholder="Optional; increases security if code is shared via weak channels" />
            <p style="margin:0.5rem 0 0 0;color:#555;">
              If you set a passphrase, recipients must know it. The passphrase is never sent to the server.
              This client uses PBKDF2 to mix the passphrase into the AES key material.
            </p>
          </div>
        </details>

        <pre id="uploadOut" style="margin-top:0.75rem;white-space:pre-wrap;"></pre>
      </section>

      <section style="margin-top:1rem;padding:1rem;border:1px solid #ddd;border-radius:10px;">
        <h2 style="margin:0 0 0.5rem 0;">Retrieve a share</h2>
        <p style="margin:0 0 0.5rem 0;">Paste a link or code:</p>
        <textarea id="codeInput" rows="3" style="width:100%;">${escapeHtml(prefillCodeOrLink)}</textarea>
        <div style="margin-top:0.75rem;display:flex;gap:0.5rem;flex-wrap:wrap;">
          <button id="btnRetrieve">Fetch and decrypt</button>
          <button id="btnDelete">Delete share (requires delete token)</button>
        </div>
        <details style="margin-top:0.75rem;">
          <summary>Delete token</summary>
          <input id="deleteTokenInput" type="text" style="width:100%;" placeholder="Paste delete token here (Base64URL)"/>
        </details>
        <pre id="retrieveOut" style="margin-top:0.75rem;white-space:pre-wrap;"></pre>
        <div id="retrieveLinks" style="margin-top:0.75rem;"></div>
      </section>

      <section style="margin-top:1rem;padding:1rem;border:1px solid #ddd;border-radius:10px;">
        <h2 style="margin:0 0 0.5rem 0;">Privacy notes</h2>
        <p style="margin:0;">
          The decryption key is contained in the fragment part of the link (after #) and is not sent to the server.
          Do not paste the full link into places that might log it. Prefer Signal; Telegram cloud chats are not end-to-end encrypted by default.
        </p>
      </section>
    </main>
  `);

  document.getElementById('btnUploadFile').addEventListener('click', () => uploadFile().catch(handleUiError('uploadOut')));
  document.getElementById('btnUploadPaste').addEventListener('click', () => uploadPaste().catch(handleUiError('uploadOut')));
  document.getElementById('btnRetrieve').addEventListener('click', () => retrieveShare().catch(handleUiError('retrieveOut')));
  document.getElementById('btnDelete').addEventListener('click', () => deleteShare().catch(handleUiError('retrieveOut')));

  document.getElementById('btnReg').addEventListener('click', () => registerPasskey().catch(handleUiError('authOut')));
  document.getElementById('btnLogin').addEventListener('click', () => loginPasskey().catch(handleUiError('authOut')));
  document.getElementById('btnLogout').addEventListener('click', () => logout().catch(handleUiError('authOut')));
}

function handleUiError(outId) {
  return (err) => {
    console.error(err);
    const el = document.getElementById(outId);
    if (el) el.textContent = `Error: ${String(err?.message || err)}`;
  };
}

/* -------------------------- Boot -------------------------- */

async function boot() {
  const fragment = (location.hash || '').replace(/^#/, '').trim();
  const prefill = fragment ? location.href : '';
  renderHome(prefill);
}

/* -------------------------- Utilities -------------------------- */

function b64urlEncode(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
  return b64;
}

function b64urlDecode(str) {
  str = String(str || '').replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
}

function hexToBytes(hex) {
  const clean = String(hex || '').toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean) || clean.length % 2 !== 0) throw new Error('Invalid hex');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i*2, i*2+2), 16);
  return out;
}

function concatBytes(...arrs) {
  const len = arrs.reduce((a,b)=>a+b.length,0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

function u32be(n) {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff;
  b[1] = (n >>> 16) & 0xff;
  b[2] = (n >>> 8) & 0xff;
  b[3] = n & 0xff;
  return b;
}

function u64beFromRandom() {
  return crypto.getRandomValues(new Uint8Array(8));
}

async function sha256(bytes) {
  const dig = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(dig);
}

async function importAesGcmKey(keyBytes32) {
  if (!(keyBytes32 instanceof Uint8Array) || keyBytes32.length !== 32) throw new Error('AES keyseed must be 32 bytes');
  return crypto.subtle.importKey(
    'raw',
    keyBytes32,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function aesGcmEncrypt(key, nonce12, plaintextBytes, aadBytes) {
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce12, additionalData: aadBytes || new Uint8Array(), tagLength: 128 },
    key,
    plaintextBytes
  );
  return new Uint8Array(ct);
}

async function aesGcmDecrypt(key, nonce12, ciphertextBytes, aadBytes) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce12, additionalData: aadBytes || new Uint8Array(), tagLength: 128 },
    key,
    ciphertextBytes
  );
  return new Uint8Array(pt);
}

/* -------------------------- Code format -------------------------- */

function makeCodePayload({ version, flags, locator24, salt16, keyseed32, delseed32, baseNonce8 }) {
  if (locator24.length !== 24) throw new Error('locator must be 24 bytes');
  if (salt16.length !== 16) throw new Error('salt must be 16 bytes');
  if (keyseed32.length !== 32) throw new Error('keyseed must be 32 bytes');
  if (delseed32.length !== 32) throw new Error('delseed must be 32 bytes');
  if (baseNonce8.length !== 8) throw new Error('baseNonce8 must be 8 bytes');

  const reserved = new Uint8Array(54);
  reserved.fill(0);
  reserved.set(baseNonce8, 0);

  const payload = concatBytes(
    new Uint8Array([version & 0xff]),
    new Uint8Array([flags & 0xff]),
    locator24,
    salt16,
    keyseed32,
    delseed32,
    reserved
  );

  if (payload.length !== APP.CODE_PAYLOAD_LEN) throw new Error('Internal code payload length mismatch');
  return payload;
}

function parseCodePayload(payload) {
  if (!(payload instanceof Uint8Array) || payload.length !== APP.CODE_PAYLOAD_LEN) {
    throw new Error('Invalid code payload length');
  }
  const version = payload[0];
  const flags = payload[1];
  const locator = payload.slice(2, 26);
  const salt = payload.slice(26, 42);
  const keyseed = payload.slice(42, 74);
  const delseed = payload.slice(74, 106);
  const reserved = payload.slice(106, 160);
  const baseNonce8 = reserved.slice(0, 8);
  return { version, flags, locator, salt, keyseed, delseed, baseNonce8 };
}

/* -------------------------- AAD and nonces -------------------------- */

function nonceForChunk(baseNonce8, chunkIndex) {
  return concatBytes(baseNonce8, u32be(chunkIndex >>> 0)); // 12 bytes
}

function nonceForManifest(baseNonce8) {
  return concatBytes(baseNonce8, new Uint8Array([0xff, 0xff, 0xff, 0xff])); // 12 bytes
}

function aadFor(locator24, version, kindByte, indexU32) {
  const prefix = new Uint8Array([0x53, 0x53]); // 'S''S'
  return concatBytes(prefix, new Uint8Array([version & 0xff]), new Uint8Array([kindByte & 0xff]), locator24, u32be(indexU32 >>> 0));
}

const AAD_KIND_CHUNK = 0x01;
const AAD_KIND_MANIFEST = 0x02;

/* -------------------------- Optional passphrase mixing -------------------------- */

async function mixPassphraseIntoKeyseed(keyseed32, salt16, passphrase) {
  const pp = String(passphrase || '');
  if (!pp) return keyseed32;

  const iterations = 250000;

  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(pp), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt16, iterations },
    baseKey,
    256
  );
  const derived = new Uint8Array(bits);

  const mixed = new Uint8Array(32);
  for (let i = 0; i < 32; i++) mixed[i] = keyseed32[i] ^ derived[i];
  return mixed;
}

/* -------------------------- Delete token derivation -------------------------- */

async function deriveDeleteToken(delseed32, salt16) {
  const info = new TextEncoder().encode('del:v1');
  const tok = await sha256(concatBytes(delseed32, salt16, info));
  return tok; // 32 bytes
}

/* -------------------------- Network detection -------------------------- */

function detectNetwork() {
  const host = (location.hostname || '').toLowerCase();
  if (host.endsWith('.onion')) return 'tor';
  if (host.endsWith('.i2p')) return 'i2p';
  return 'clearnet';
}

/* -------------------------- PoW (Tor/I2P) -------------------------- */

function leadingZeroBits(bytes32) {
  let bits = 0;
  for (let i = 0; i < 32; i++) {
    const v = bytes32[i];
    if (v === 0) { bits += 8; continue; }
    for (let b = 7; b >= 0; b--) {
      if ((v & (1 << b)) === 0) bits++;
      else return bits;
    }
  }
  return bits;
}

async function solvePow(challenge32, locator24, difficultyBits, progressCb) {
  let attempts = 0;
  while (true) {
    const nonce = u64beFromRandom();
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', concatBytes(challenge32, locator24, nonce)));
    attempts++;
    if (attempts % 500 === 0 && typeof progressCb === 'function') progressCb(attempts);
    if (leadingZeroBits(digest) >= difficultyBits) return nonce;
    if (attempts % 200 === 0) await new Promise(r => setTimeout(r, 0));
  }
}

/* -------------------------- API helpers -------------------------- */

async function apiJson(path, method, body, token) {
  const headers = { 'Accept': 'application/json' };
  if (body !== null && body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(path, { method, headers, body: body !== null && body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text().catch(() => '');
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = {}; }
  if (!res.ok) throw new Error(data?.error || `HTTP ${res.status}`);
  return data;
}

async function apiPutBytes(path, bytes, token) {
  const headers = { 'Content-Type': 'application/octet-stream' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(path, { method: 'PUT', headers, body: bytes });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(txt || `HTTP ${res.status}`);
  }
}

async function apiGetBytes(path) {
  const res = await fetch(path, { method: 'GET', headers: { 'Cache-Control': 'no-store' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

/* -------------------------- Upload: file -------------------------- */

async function uploadFile() {
  const out = document.getElementById('uploadOut');
  const file = document.getElementById('fileInput')?.files?.[0];
  if (!file) throw new Error('Select a file first.');

  out.textContent = '';

  const hours = clampInt(document.getElementById('hours')?.value, 1, APP.MAX_HOURS, APP.DEFAULT_HOURS);
  const expiresEpoch = Math.floor(Date.now() / 1000) + (hours * 3600);

  const chunkSize = clampChunkSize(parseInt(document.getElementById('chunkSize')?.value || String(APP.CHUNK_SIZE_DEFAULT), 10));

  const passphrase = String(document.getElementById('passphrase')?.value || '');
  const usePowAllAnon = !!document.getElementById('usePowAllAnon')?.checked;

  const network = detectNetwork();

  const locator = crypto.getRandomValues(new Uint8Array(24));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyseedRaw = crypto.getRandomValues(new Uint8Array(32));
  const delseed = crypto.getRandomValues(new Uint8Array(32));
  const baseNonce8 = crypto.getRandomValues(new Uint8Array(8));

  const keyseed = await mixPassphraseIntoKeyseed(keyseedRaw, salt, passphrase);
  const encKey = await importAesGcmKey(keyseed);

  const deleteToken = await deriveDeleteToken(delseed, salt);
  const deleteTokenHash = await sha256(deleteToken);

  const sizeBytes = file.size;
  const chunkCount = Math.ceil(sizeBytes / chunkSize);

  let powPayload = {};
  if (network === 'tor' || network === 'i2p' || usePowAllAnon) {
    out.textContent += `Requesting proof-of-work challenge (${network}${usePowAllAnon && network === 'clearnet' ? ', forced' : ''})...\\n`;
    const pow = await apiJson('/api/pow/challenge', 'GET');
    const challenge = b64urlDecode(pow.challenge_b64u);
    out.textContent += `Solving proof-of-work (difficulty ${pow.difficulty_bits} bits)...\\n`;
    const nonce = await solvePow(challenge, locator, pow.difficulty_bits, (attempts) => {
      out.textContent = out.textContent.split('\\n').slice(0, 2).join('\\n') + `\\nPoW attempts: ${attempts}\\n`;
    });
    powPayload = {
      network: (network === 'clearnet' && usePowAllAnon) ? 'clearnet' : network,
      pow_challenge_id_b64u: pow.challenge_id_b64u,
      pow_challenge_b64u: pow.challenge_b64u,
      pow_nonce_b64u: b64urlEncode(nonce),
    };
    out.textContent += `PoW solved.\\n`;
  }

  out.textContent += `Initialising share...\\n`;

  const init = await apiJson('/api/share/init', 'POST', {
    locator_hex: bytesToHex(locator),
    type: 'file',
    size_bytes: sizeBytes,
    chunk_size: chunkSize,
    expires_at_epoch: expiresEpoch,
    delete_token_hash_b64u: b64urlEncode(deleteTokenHash),
    ...powPayload
  });

  if (String(init.locator_hex || '').toLowerCase() !== bytesToHex(locator)) {
    throw new Error('Server did not accept the provided locator (collision or validation failure).');
  }

  out.textContent += `Encrypting and uploading ${chunkCount} chunks...\\n`;

  for (let i = 0; i < chunkCount; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, sizeBytes);
    const plain = new Uint8Array(await file.slice(start, end).arrayBuffer());

    const nonce12 = nonceForChunk(baseNonce8, i);
    const aad = aadFor(locator, APP.VERSION, AAD_KIND_CHUNK, i);
    const cipher = await aesGcmEncrypt(encKey, nonce12, plain, aad);

    await apiPutBytes(`/api/share/${init.locator_hex}/chunk/${i}`, cipher, init.upload_token);

    if ((i + 1) % 5 === 0 || i === chunkCount - 1) {
      out.textContent += `Uploaded chunk ${i + 1} of ${chunkCount}\\n`;
    }
  }

  const manifest = {
    v: APP.VERSION,
    type: 'file',
    size: sizeBytes,
    chunk_size: chunkSize,
    chunk_count: chunkCount,
    name: file.name || null,
  };

  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
  const mNonce12 = nonceForManifest(baseNonce8);
  const mAad = aadFor(locator, APP.VERSION, AAD_KIND_MANIFEST, APP.MANIFEST_INDEX);
  const manifestCipher = await aesGcmEncrypt(encKey, mNonce12, manifestBytes, mAad);

  await apiPutBytes(`/api/share/${init.locator_hex}/manifest`, manifestCipher, init.upload_token);
  await apiJson(`/api/share/${init.locator_hex}/complete`, 'POST', null, init.upload_token);

  const payload = makeCodePayload({
    version: APP.VERSION,
    flags: APP.FLAG_FILE,
    locator24: locator,
    salt16: salt,
    keyseed32: keyseedRaw,
    delseed32: delseed,
    baseNonce8: baseNonce8
  });

  const code = b64urlEncode(payload);
  const link = `${location.origin}/#${code}`;

  out.textContent += `\\nShare link (copy and send):\\n${link}\\n`;
  out.textContent += `\\nDelete token (keep private):\\n${b64urlEncode(deleteToken)}\\n`;

  out.textContent += `\\nNotes:\\n`;
  out.textContent += `- The server cannot decrypt content.\\n`;
  out.textContent += `- If you set a passphrase, the recipient must know it.\\n`;
}

/* -------------------------- Upload: paste -------------------------- */

async function uploadPaste() {
  const out = document.getElementById('uploadOut');
  const text = String(document.getElementById('pasteInput')?.value || '');
  if (!text.trim()) throw new Error('Paste content is empty.');

  out.textContent = '';

  const hours = clampInt(document.getElementById('hours')?.value, 1, APP.MAX_HOURS, APP.DEFAULT_HOURS);
  const expiresEpoch = Math.floor(Date.now() / 1000) + (hours * 3600);

  const chunkSize = clampChunkSize(parseInt(document.getElementById('chunkSize')?.value || String(APP.CHUNK_SIZE_DEFAULT), 10));

  const passphrase = String(document.getElementById('passphrase')?.value || '');
  const usePowAllAnon = !!document.getElementById('usePowAllAnon')?.checked;

  const network = detectNetwork();

  const plainAll = new TextEncoder().encode(text);
  const sizeBytes = plainAll.length;
  const chunkCount = Math.ceil(sizeBytes / chunkSize);

  const locator = crypto.getRandomValues(new Uint8Array(24));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyseedRaw = crypto.getRandomValues(new Uint8Array(32));
  const delseed = crypto.getRandomValues(new Uint8Array(32));
  const baseNonce8 = crypto.getRandomValues(new Uint8Array(8));

  const keyseed = await mixPassphraseIntoKeyseed(keyseedRaw, salt, passphrase);
  const encKey = await importAesGcmKey(keyseed);

  const deleteToken = await deriveDeleteToken(delseed, salt);
  const deleteTokenHash = await sha256(deleteToken);

  let powPayload = {};
  if (network === 'tor' || network === 'i2p' || usePowAllAnon) {
    out.textContent += `Requesting proof-of-work challenge...\\n`;
    const pow = await apiJson('/api/pow/challenge', 'GET');
    const challenge = b64urlDecode(pow.challenge_b64u);
    out.textContent += `Solving proof-of-work (difficulty ${pow.difficulty_bits} bits)...\\n`;
    const nonce = await solvePow(challenge, locator, pow.difficulty_bits);
    powPayload = {
      network: (network === 'clearnet' && usePowAllAnon) ? 'clearnet' : network,
      pow_challenge_id_b64u: pow.challenge_id_b64u,
      pow_challenge_b64u: pow.challenge_b64u,
      pow_nonce_b64u: b64urlEncode(nonce),
    };
    out.textContent += `PoW solved.\\n`;
  }

  out.textContent += `Initialising share...\\n`;
  const init = await apiJson('/api/share/init', 'POST', {
    locator_hex: bytesToHex(locator),
    type: 'paste',
    size_bytes: sizeBytes,
    chunk_size: chunkSize,
    expires_at_epoch: expiresEpoch,
    delete_token_hash_b64u: b64urlEncode(deleteTokenHash),
    ...powPayload
  });

  if (String(init.locator_hex || '').toLowerCase() !== bytesToHex(locator)) {
    throw new Error('Server did not accept the provided locator (collision or validation failure).');
  }

  out.textContent += `Encrypting and uploading ${chunkCount} chunks...\\n`;
  for (let i = 0; i < chunkCount; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, sizeBytes);
    const plain = plainAll.slice(start, end);

    const nonce12 = nonceForChunk(baseNonce8, i);
    const aad = aadFor(locator, APP.VERSION, AAD_KIND_CHUNK, i);
    const cipher = await aesGcmEncrypt(encKey, nonce12, plain, aad);

    await apiPutBytes(`/api/share/${init.locator_hex}/chunk/${i}`, cipher, init.upload_token);
    if ((i + 1) % 5 === 0 || i === chunkCount - 1) {
      out.textContent += `Uploaded chunk ${i + 1} of ${chunkCount}\\n`;
    }
  }

  const manifest = {
    v: APP.VERSION,
    type: 'paste',
    size: sizeBytes,
    chunk_size: chunkSize,
    chunk_count: chunkCount,
    name: null
  };

  const manifestBytes = new TextEncoder().encode(JSON.stringify(manifest));
  const mNonce12 = nonceForManifest(baseNonce8);
  const mAad = aadFor(locator, APP.VERSION, AAD_KIND_MANIFEST, APP.MANIFEST_INDEX);
  const manifestCipher = await aesGcmEncrypt(encKey, mNonce12, manifestBytes, mAad);

  await apiPutBytes(`/api/share/${init.locator_hex}/manifest`, manifestCipher, init.upload_token);
  await apiJson(`/api/share/${init.locator_hex}/complete`, 'POST', null, init.upload_token);

  const payload = makeCodePayload({
    version: APP.VERSION,
    flags: APP.FLAG_PAS,
    locator24: locator,
    salt16: salt,
    keyseed32: keyseedRaw,
    delseed32: delseed,
    baseNonce8: baseNonce8
  });

  const code = b64urlEncode(payload);
  const link = `${location.origin}/#${code}`;

  out.textContent += `\\nShare link (copy and send):\\n${link}\\n`;
  out.textContent += `\\nDelete token (keep private):\\n${b64urlEncode(deleteToken)}\\n`;
}

/* -------------------------- Retrieve -------------------------- */

async function retrieveShare() {
  const out = document.getElementById('retrieveOut');
  const links = document.getElementById('retrieveLinks');
  out.textContent = '';
  if (links) links.innerHTML = '';

  const input = String(document.getElementById('codeInput')?.value || '').trim();
  const passphrase = String(document.getElementById('passphrase')?.value || '');

  const code = extractCodeFromInput(input);
  if (!code) throw new Error('Provide a valid link or code.');

  let payloadBytes;
  try { payloadBytes = b64urlDecode(code); } catch { throw new Error('Invalid code.'); }

  const parsed = parseCodePayload(payloadBytes);
  if (parsed.version !== APP.VERSION) throw new Error('Unsupported code version.');

  const mixedKeyseed = await mixPassphraseIntoKeyseed(parsed.keyseed, parsed.salt, passphrase);
  const encKey = await importAesGcmKey(mixedKeyseed);

  const locatorHex = bytesToHex(parsed.locator);

  const manifestCipher = await apiGetBytes(`/api/share/${locatorHex}/manifest`);
  const mNonce12 = nonceForManifest(parsed.baseNonce8);
  const mAad = aadFor(parsed.locator, parsed.version, AAD_KIND_MANIFEST, APP.MANIFEST_INDEX);

  let manifestPlain;
  try {
    manifestPlain = await aesGcmDecrypt(encKey, mNonce12, manifestCipher, mAad);
  } catch {
    throw new Error('Failed to decrypt manifest (wrong code/passphrase or tampered data).');
  }

  let manifest;
  try { manifest = JSON.parse(new TextDecoder().decode(manifestPlain)); } catch { throw new Error('Manifest parse failed.'); }

  const chunkCount = manifest.chunk_count;
  const totalSize = manifest.size;
  const type = manifest.type;

  if (!Number.isInteger(chunkCount) || chunkCount <= 0) throw new Error('Invalid manifest (chunk_count).');
  if (!Number.isInteger(totalSize) || totalSize < 0) throw new Error('Invalid manifest (size).');

  out.textContent = `Decrypting ${chunkCount} chunks...\\n`;

  const parts = [];
  for (let i = 0; i < chunkCount; i++) {
    const cipher = await apiGetBytes(`/api/share/${locatorHex}/chunk/${i}`);
    const nonce12 = nonceForChunk(parsed.baseNonce8, i);
    const aad = aadFor(parsed.locator, parsed.version, AAD_KIND_CHUNK, i);

    let plain;
    try {
      plain = await aesGcmDecrypt(encKey, nonce12, cipher, aad);
    } catch {
      throw new Error(`Failed to decrypt chunk ${i} (wrong code/passphrase or tampered data).`);
    }

    parts.push(plain);

    if ((i + 1) % 5 === 0 || i === chunkCount - 1) {
      out.textContent = `Decrypting ${chunkCount} chunks...\\nDecrypted ${i + 1} of ${chunkCount}\\n`;
    }
  }

  const outBytes = new Uint8Array(totalSize);
  let off = 0;
  for (const p of parts) {
    outBytes.set(p, off);
    off += p.length;
  }

  if (type === 'paste') {
    const text = new TextDecoder().decode(outBytes);
    out.textContent += `\\nPaste decrypted successfully.\\n`;
    if (links) {
      links.innerHTML = `
        <h3 style="margin:0.5rem 0;">Paste content</h3>
        <textarea rows="10" style="width:100%;">${escapeHtml(text)}</textarea>
      `;
    }
    return;
  }

  const name = manifest.name || 'download.bin';
  const blob = new Blob([outBytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);

  out.textContent += `\\nFile ready: ${name}\\n`;

  if (links) {
    links.innerHTML = `
      <p><a href="${url}" download="${escapeHtml(name)}">Download ${escapeHtml(name)}</a></p>
      <p style="color:#555;margin:0;">If this is a sensitive file, consider saving it locally and deleting the share promptly.</p>
    `;
  }
}

function extractCodeFromInput(input) {
  const s = String(input || '').trim();
  if (!s) return '';
  const hashIdx = s.indexOf('#');
  if (hashIdx >= 0) return s.slice(hashIdx + 1).trim();
  return s;
}

/* -------------------------- Delete share -------------------------- */

async function deleteShare() {
  const out = document.getElementById('retrieveOut');
  out.textContent = '';

  const input = String(document.getElementById('codeInput')?.value || '').trim();
  const code = extractCodeFromInput(input);
  if (!code) throw new Error('Provide a valid link or code (to get the locator).');

  let payloadBytes;
  try { payloadBytes = b64urlDecode(code); } catch { throw new Error('Invalid code.'); }

  const parsed = parseCodePayload(payloadBytes);
  const locatorHex = bytesToHex(parsed.locator);

  const delTok = String(document.getElementById('deleteTokenInput')?.value || '').trim();
  if (!delTok) throw new Error('Provide the delete token.');

  await apiJson(`/api/share/${locatorHex}/delete`, 'POST', { delete_token_b64u: delTok });

  out.textContent = 'Share deleted successfully.';
}

/* -------------------------- Auth (WebAuthn client) -------------------------- */

function bufToB64u(buf) { return b64urlEncode(new Uint8Array(buf)); }
function b64uToBuf(b64u) { return b64urlDecode(b64u).buffer; }

async function registerPasskey() {
  const out = document.getElementById('authOut');
  out.textContent = '';

  if (!('credentials' in navigator) || !('create' in navigator.credentials)) {
    throw new Error('WebAuthn is not supported in this browser.');
  }

  out.textContent = 'Requesting registration options...\\n';
  const opts = await apiJson('/api/auth/register/options', 'GET');

  const publicKey = {
    rp: opts.rp,
    user: {
      id: b64uToBuf(opts.user.id_b64u),
      name: opts.user.name,
      displayName: opts.user.displayName
    },
    challenge: b64uToBuf(opts.challenge_b64u),
    pubKeyCredParams: opts.pubKeyCredParams,
    timeout: opts.timeout,
    attestation: opts.attestation,
    authenticatorSelection: opts.authenticatorSelection,
  };

  out.textContent += 'Creating passkey...\\n';
  const cred = await navigator.credentials.create({ publicKey });
  if (!cred) throw new Error('Registration cancelled.');

  const att = cred.response;

  const payload = {
    credential_id_b64u: b64urlEncode(new Uint8Array(cred.rawId)),
    attestation_object_b64u: bufToB64u(att.attestationObject),
    client_data_json_b64u: bufToB64u(att.clientDataJSON),
  };

  out.textContent += 'Verifying with server...\\n';
  await apiJson('/api/auth/register/verify', 'POST', payload);

  out.textContent += 'Registered and signed in.\\n';
}

async function loginPasskey() {
  const out = document.getElementById('authOut');
  out.textContent = '';

  if (!('credentials' in navigator) || !('get' in navigator.credentials)) {
    throw new Error('WebAuthn is not supported in this browser.');
  }

  out.textContent = 'Requesting login options...\\n';
  const opts = await apiJson('/api/auth/login/options', 'GET');

  const publicKey = {
    challenge: b64uToBuf(opts.challenge_b64u),
    timeout: opts.timeout,
    userVerification: opts.userVerification,
    allowCredentials: (opts.allowCredentials || []).map(c => ({
      type: c.type,
      id: b64uToBuf(c.id_b64u),
    })),
  };

  out.textContent += 'Requesting assertion...\\n';
  const assertion = await navigator.credentials.get({ publicKey });
  if (!assertion) throw new Error('Login cancelled.');

  const res = assertion.response;
  const payload = {
    credential_id_b64u: b64urlEncode(new Uint8Array(assertion.rawId)),
    authenticator_data_b64u: bufToB64u(res.authenticatorData),
    client_data_json_b64u: bufToB64u(res.clientDataJSON),
    signature_b64u: bufToB64u(res.signature),
    user_handle_b64u: res.userHandle ? bufToB64u(res.userHandle) : null,
  };

  out.textContent += 'Verifying with server...\\n';
  await apiJson('/api/auth/login/verify', 'POST', payload);

  out.textContent += 'Signed in.\\n';
}

async function logout() {
  const out = document.getElementById('authOut');
  out.textContent = '';
  await apiJson('/api/auth/logout', 'POST', {});
  out.textContent = 'Signed out.\\n';
}

/* -------------------------- Helpers -------------------------- */

function clampInt(v, min, max, fallback) {
  const n = parseInt(String(v ?? ''), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, n));
}

function clampChunkSize(n) {
  const allowed = [256*1024, 512*1024, 1024*1024, 2*1024*1024, 4*1024*1024];
  if (!allowed.includes(n)) return APP.CHUNK_SIZE_DEFAULT;
  return n;
}
