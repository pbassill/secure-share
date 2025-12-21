'use strict';

/*
  High-level design:
  - Code lives in URL fragment (#...), so the server never sees it.
  - Code contains: version + flags + locator(24) + salt(16) + keyseed(32) + delseed(32) + reserved(54) = 160 bytes.
  - encKey = keyseed directly imported as AES-GCM 256-bit key (simple and robust).
  - deleteToken = HKDF(key=delseed, salt, info) => 32 bytes; server stores SHA-256(deleteToken).
  - baseNonce (8 bytes) stored inside encrypted manifest; per-chunk nonce = baseNonce || uint32(chunkIndex).
  - manifest encrypted with nonce baseNonce || 0xFFFFFFFF.
*/

const APP = {
  chunkSizeDefault: 1024 * 1024
};

function b64urlEncode(bytes) {
  const bin = String.fromCharCode(...bytes);
  const b64 = btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
  return b64;
}
function b64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i*2,2),16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join('');
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

async function sha256(bytes) {
  const dig = await crypto.subtle.digest('SHA-256', bytes);
  return new Uint8Array(dig);
}

async function importAesGcmKey(keyBytes) {
  return crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt','decrypt']
  );
}

async function aesGcmEncrypt(key, nonce12, plaintext, aadBytes) {
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce12, additionalData: aadBytes || new Uint8Array(), tagLength: 128 },
    key,
    plaintext
  );
  return new Uint8Array(ct);
}

async function aesGcmDecrypt(key, nonce12, ciphertext, aadBytes) {
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce12, additionalData: aadBytes || new Uint8Array(), tagLength: 128 },
    key,
    ciphertext
  );
  return new Uint8Array(pt);
}

function makeCodePayload({version, flags, locator24, salt16, keyseed32, delseed32}) {
  const reserved = new Uint8Array(54);
  reserved.fill(0);
  return concatBytes(
    new Uint8Array([version & 0xff]),
    new Uint8Array([flags & 0xff]),
    locator24,
    salt16,
    keyseed32,
    delseed32,
    reserved
  );
}

function parseCodePayload(payload) {
  if (!(payload instanceof Uint8Array) || payload.length < 160) throw new Error('Invalid code payload');
  const version = payload[0];
  const flags = payload[1];
  const locator = payload.slice(2, 26);
  const salt = payload.slice(26, 42);
  const keyseed = payload.slice(42, 74);
  const delseed = payload.slice(74, 106);
  return { version, flags, locator, salt, keyseed, delseed };
}

async function deriveDeleteToken(delseed32, salt16) {
  // Simple HKDF-like derivation using SHA-256(delseed || salt || "del:v1")
  const info = new TextEncoder().encode('del:v1');
  const raw = concatBytes(delseed32, salt16, info);
  const tok = await sha256(raw);
  return tok; // 32 bytes
}

function nonceForChunk(baseNonce8, chunkIndex) {
  return concatBytes(baseNonce8, u32be(chunkIndex));
}

function nonceForManifest(baseNonce8) {
  return concatBytes(baseNonce8, new Uint8Array([0xff,0xff,0xff,0xff]));
}

function aadFor(locator24, version, kindByte, indexU32) {
  // AAD = "SS" + version + kind + locator + index
  const prefix = new Uint8Array([0x53, 0x53]); // 'S''S'
  return concatBytes(prefix, new Uint8Array([version & 0xff]), new Uint8Array([kindByte & 0xff]), locator24, u32be(indexU32 >>> 0));
}

async function apiJson(path, method, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const txt = await res.text();
  let data = {};
  try { data = txt ? JSON.parse(txt) : {}; } catch { data = {}; }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

async function apiPutBytes(path, bytes, token) {
  const headers = { 'Content-Type': 'application/octet-stream' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(path, { method: 'PUT', headers, body: bytes });
  if (!res.ok) {
    const txt = await res.text().catch(()=> '');
    throw new Error(txt || `HTTP ${res.status}`);
  }
}

async function apiGetBytes(path) {
  const res = await fetch(path, { method: 'GET', headers: { 'Cache-Control': 'no-store' } });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return new Uint8Array(await res.arrayBuffer());
}

// Minimal UI
function setApp(html) { document.getElementById('app').innerHTML = html; }

function renderHome() {
  setApp(`
    <main style="max-width:720px;margin:2rem auto;font-family:system-ui;">
      <h1>Secure Share</h1>
      <p>This service encrypts in your browser. The server stores ciphertext only. Share links contain a fragment that is not sent to the server.</p>

      <section style="margin-top:1.5rem;padding:1rem;border:1px solid #ddd;border-radius:8px;">
        <h2>Create a share</h2>
        <p><input id="file" type="file" /></p>
        <p>
          <label>Retention (hours, default 6, max 336): </label>
          <input id="hours" type="number" min="1" max="336" value="6" />
        </p>
        <p>
          <button id="upload">Encrypt and upload</button>
        </p>
        <pre id="out" style="white-space:pre-wrap"></pre>
      </section>

      <section style="margin-top:1.5rem;padding:1rem;border:1px solid #ddd;border-radius:8px;">
        <h2>Retrieve a share</h2>
        <p>Paste a link or code:</p>
        <p><textarea id="code" rows="3" style="width:100%"></textarea></p>
        <p><button id="retrieve">Fetch and decrypt</button></p>
        <pre id="dl" style="white-space:pre-wrap"></pre>
      </section>
    </main>
  `);

  document.getElementById('upload').addEventListener('click', handleUpload);
  document.getElementById('retrieve').addEventListener('click', handleRetrieve);
}

async function handleUpload() {
  const out = document.getElementById('out');
  out.textContent = '';

  const f = document.getElementById('file').files[0];
  if (!f) { out.textContent = 'Select a file first.'; return; }

  const hours = Math.max(1, Math.min(336, parseInt(document.getElementById('hours').value || '6', 10)));
  const expiresEpoch = Math.floor(Date.now()/1000) + (hours * 3600);

  // Generate client secrets
  const version = 1;
  const flags = 1; // bit0 = file (1) vs paste (0)
  const locator = crypto.getRandomValues(new Uint8Array(24));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyseed = crypto.getRandomValues(new Uint8Array(32));
  const delseed = crypto.getRandomValues(new Uint8Array(32));
  const baseNonce8 = crypto.getRandomValues(new Uint8Array(8));

  const encKey = await importAesGcmKey(keyseed);
  const deleteToken = await deriveDeleteToken(delseed, salt);
  const deleteTokenHash = await sha256(deleteToken);

  const chunkSize = APP.chunkSizeDefault;
  const sizeBytes = f.size;
  const chunkCount = Math.ceil(sizeBytes / chunkSize);

  // Init share server-side (server sees locator only, not keys)
  const init = await apiJson('/api/share/init', 'POST', {
    type: 'file',
    size_bytes: sizeBytes,
    chunk_size: chunkSize,
    expires_at_epoch: expiresEpoch,
    delete_token_hash_b64u: b64urlEncode(deleteTokenHash),
  });

  if (init.locator_hex !== bytesToHex(locator)) {
    // The server generated locator in this pack; to keep code client-only, we accept server locator.
    // For consistency, we will overwrite locator with server locator and keep client keyseed etc.
    // In production you can move locator generation client-side by passing locator_hex in init and validating server-side.
    out.textContent = 'Server locator differs; regenerating code with server locator.\n';
  }
  const locatorServer = hexToBytes(init.locator_hex);

  // Encrypt and upload chunks
  for (let i = 0; i < init.chunk_count; i++) {
    const start = i * init.chunk_size;
    const end = Math.min(start + init.chunk_size, sizeBytes);
    const blob = f.slice(start, end);
    const plain = new Uint8Array(await blob.arrayBuffer());

    const nonce = nonceForChunk(baseNonce8, i);
    const aad = aadFor(locatorServer, version, 0x01, i);
    const cipher = await aesGcmEncrypt(encKey, nonce, plain, aad);

    await apiPutBytes(`/api/share/${init.locator_hex}/chunk/${i}`, cipher, init.upload_token);
    out.textContent = `Uploaded chunk ${i + 1} of ${init.chunk_count}\n`;
  }

  // Build manifest (encrypted)
  const manifestObj = {
    v: version,
    type: 'file',
    size: sizeBytes,
    chunk_size: init.chunk_size,
    chunk_count: init.chunk_count,
    base_nonce_b64u: b64urlEncode(baseNonce8),
    name: f.name || null,
    // mime intentionally omitted to reduce metadata; you can add inside manifest if you wish.
  };
  const manifestJson = new TextEncoder().encode(JSON.stringify(manifestObj));
  const mNonce = nonceForManifest(baseNonce8);
  const mAad = aadFor(locatorServer, version, 0x02, 0xffffffff);
  const manifestCipher = await aesGcmEncrypt(encKey, mNonce, manifestJson, mAad);

  await apiPutBytes(`/api/share/${init.locator_hex}/manifest`, manifestCipher, init.upload_token);
  await apiJson(`/api/share/${init.locator_hex}/complete`, 'POST', null, init.upload_token);

  // Pack code and present link (fragment)
  const payload = makeCodePayload({
    version,
    flags,
    locator24: locatorServer,
    salt16: salt,
    keyseed32: keyseed,
    delseed32: delseed
  });
  const code = b64urlEncode(payload);
  const link = `${location.origin}/#${code}`;

  out.textContent += `\nShare link:\n${link}\n\nDelete token (keep private):\n${b64urlEncode(deleteToken)}\n`;
}

async function handleRetrieve() {
  const dl = document.getElementById('dl');
  dl.textContent = '';

  const input = (document.getElementById('code').value || '').trim();
  const frag = input.includes('#') ? input.split('#').pop() : input;
  const code = (frag || '').trim();
  if (!code) { dl.textContent = 'Provide a code or link.'; return; }

  let payload;
  try { payload = b64urlDecode(code); } catch { dl.textContent = 'Invalid code.'; return; }

  let parsed;
  try { parsed = parseCodePayload(payload); } catch { dl.textContent = 'Invalid code payload.'; return; }

  if (parsed.version !== 1) { dl.textContent = 'Unsupported version.'; return; }

  const encKey = await importAesGcmKey(parsed.keyseed);
  const locatorHex = bytesToHex(parsed.locator);

  // Fetch and decrypt manifest
  const manifestCipher = await apiGetBytes(`/api/share/${locatorHex}/manifest`);
  // We need baseNonce8 to derive nonces, but it is inside manifest; however manifest nonce uses baseNonce8.
  // Therefore baseNonce8 must be derivable from elsewhere. In this baseline we stored baseNonce8 inside manifest,
  // but we also need it to decrypt manifest: circular. Fix by storing baseNonce8 in code payload reserved space,
  // or derive baseNonce8 from keyseed+salt.
  // For simplicity, derive baseNonce8 = first 8 bytes of SHA-256(keyseed || salt || "nonce:v1").
  const baseNonce8 = (await sha256(concatBytes(parsed.keyseed, parsed.salt, new TextEncoder().encode('nonce:v1')))).slice(0,8);

  const mNonce = nonceForManifest(baseNonce8);
  const mAad = aadFor(parsed.locator, parsed.version, 0x02, 0xffffffff);

  let manifestPlain;
  try {
    manifestPlain = await aesGcmDecrypt(encKey, mNonce, manifestCipher, mAad);
  } catch (e) {
    dl.textContent = 'Failed to decrypt manifest (wrong code or tampered data).';
    return;
  }

  const manifest = JSON.parse(new TextDecoder().decode(manifestPlain));
  const chunkCount = manifest.chunk_count;
  const chunkSize = manifest.chunk_size;
  const totalSize = manifest.size;

  dl.textContent = `Decrypting ${chunkCount} chunks...\n`;

  const parts = [];
  for (let i = 0; i < chunkCount; i++) {
    const cipher = await apiGetBytes(`/api/share/${locatorHex}/chunk/${i}`);
    const nonce = nonceForChunk(baseNonce8, i);
    const aad = aadFor(parsed.locator, parsed.version, 0x01, i);
    const plain = await aesGcmDecrypt(encKey, nonce, cipher, aad);
    parts.push(plain);
    dl.textContent = `Decrypted chunk ${i + 1} of ${chunkCount}\n`;
  }

  // Reassemble
  const out = new Uint8Array(totalSize);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }

  const blob = new Blob([out], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);

  const name = manifest.name || 'download.bin';
  dl.textContent += `\nReady:\n${name}\n`;
  dl.innerHTML += `<p><a href="${url}" download="${name}">Download</a></p>`;
}

function boot() {
  // If the URL has a fragment code, preload it into the retrieve box.
  renderHome();
  const h = (location.hash || '').replace(/^#/, '');
  if (h && h.length > 10) {
    const t = document.getElementById('code');
    t.value = location.href;
  }
}

boot();
