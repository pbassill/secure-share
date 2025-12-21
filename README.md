# Implementation

You should enforce body size and timeouts at the web server. For 100 MB anonymous with chunked PUTs, you are typically sending 1 MiB bodies repeatedly, so you can keep a moderate max request size (for example 8–16 MiB). This reduces DoS surface. If you later support larger authenticated shares with larger chunks, increase cautiously.

Example vhost snippet:

```
# Prevent large single-request uploads; chunked uploads should stay small.
LimitRequestBody 16777216

# Timeouts appropriate for chunk PUTs
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500

# Disable directory listings, ensure no storage path is under DocumentRoot.
<Directory "/var/www/secure-share/public">
    Options -Indexes
    AllowOverride None
    Require all granted
</Directory>

# Security headers (some already set in PHP; it is fine to enforce here too)
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "no-referrer"

# Avoid caching
Header always set Cache-Control "no-store"
```
Cron entry example:
```
*/5 * * * * /usr/bin/php /var/www/secure-share/cron/expire.php >/dev/null 2>&1
```

If you serve Tor and I2P, ensure the SPA does not call out to any external resources and that absolute URLs are not pointing to clearnet endpoints when accessed via onion/i2p hostnames.

# Design

## 1) System invariants

The server must never receive the decryption key. The retrieval code must contain both the locator and the key, but the key must remain client-only; therefore the shared link should place the entire code in the URL fragment, for example https://example.tld/#<CODE>. The SPA reads location.hash, extracts locator and key, requests ciphertext by locator, and decrypts locally.

All stored content is ciphertext, including filenames, paste text, MIME types, and any descriptive metadata; only operational metadata exists server-side (expiry, sizes, chunk count, status, counters).

Chunk storage is local disk, outside the web root, with strict permissions and no direct static serving. All chunk retrieval is via a PHP endpoint that streams bytes.

## 2) Retrieval code (“256 characters”): versioned, fixed-format, Base64URL

You can standardise on a fixed-length Base64URL string for UX. In practice, you will encode a fixed-length binary payload and Base64URL it without padding. If you want exactly 256 characters, you can fix the binary size to yield that length under Base64URL; however, it is not a security requirement. The security requirement is high entropy and versioning.

Recommended binary payload layout (fixed length, 160 bytes is more than sufficient and will produce a long Base64URL code):

V (1 byte): version, start at 1
F (1 byte): flags (file vs paste; passphrase required; etc.)
L (24 bytes): locator (192-bit random)
S (16 bytes): salt (for optional passphrase KDF and key derivation binding)
K (32 bytes): content key seed (256-bit random)
D (32 bytes): delete token seed (256-bit random)
R (54 bytes): reserved for future rotation (alg IDs, KDF params, etc.)

Client derives:
enc_key = HKDF-SHA-256(ikm=K, salt=S, info="enc:v1", length=32)
del_token = HKDF-SHA-256(ikm=D, salt=S, info="del:v1", length=32)

If a passphrase is supplied, incorporate it by deriving K from K || Argon2id(passphrase, S) (or, if you want to stay strictly within WebCrypto primitives, PBKDF2 with high iterations; Argon2id is preferable but not natively in WebCrypto and would require a vetted JS implementation). The privacy-friendly compromise for a browser-only service is: optional passphrase uses PBKDF2-SHA-256 with a high iteration count and explicit UI warnings, and you keep the door open to a future Argon2 upgrade via the version byte and reserved space.

The server stores only L (locator), and a hash of del_token for revocation.

## 3) Encryption format: AES-256-GCM chunking plus encrypted manifest

### Chunk size

Use 1 MiB chunks by default. For 100 MB anonymous, that is roughly 100 chunks, which is fine. For larger authenticated uploads, the chunk count grows linearly; you can raise chunk size for large files while keeping a sensible ceiling (for example 4 MiB).

### Nonce strategy

AES-GCM requires a unique nonce per encryption under the same key. Use a 96-bit nonce composed of:
nonce = base_nonce(8 bytes random) || counter(4 bytes big-endian chunk_index)

Store base_nonce inside the encrypted manifest. Do not store it in plaintext server-side.

### Associated Data (AAD)

Bind immutable metadata into the authentication tag to prevent tampering:
AAD could be: version || locator || chunk_index || manifest_id
In practice, you can use a compact binary AAD. The important point is that the client reconstructs AAD identically during decrypt.

### Manifest

Create a manifest JSON (or CBOR if you prefer compactness) containing:
type (“file” or “paste”), name (optional), mime (optional), size, chunk_size, chunk_count, base_nonce, and optionally sha256 of plaintext (privacy trade-off: hash can be used for correlation if content repeats; many privacy services omit it). For paste, the “file” is simply text content encrypted as chunks with a small size.

Encrypt the manifest with AES-256-GCM using nonce base_nonce || 0xFFFFFFFF (a reserved counter value not used by chunk indices) and AAD that binds it to the locator and version. Store the encrypted manifest as chunk -1 or a separate file on disk; do not store it in MySQL as large text.

## 4) Local disk storage layout

Choose a storage root, for example /var/lib/secure-share/storage. This must not be under the web root.

Directory structure:
/var/lib/secure-share/storage/<L_hex_prefix>/<L_hex_full>/

Where L_hex_prefix is first 2–4 bytes to avoid too many directories in one level.

Inside:
manifest.bin (ciphertext)
chunk_000000.bin … chunk_N.bin (ciphertext)

Permissions:
Owner www-data, mode 0700 on directories, 0600 on files.

Never serve these files directly. Always stream through PHP after authorisation and validation (authorisation here is simply “does the share exist and is not expired”; key possession is enforced client-side).

## 5) MySQL schema (minimal, enforce expiry, support throttling and deletion)
shares

locator BINARY(24) PRIMARY KEY
created_at DATETIME NOT NULL
expires_at DATETIME NOT NULL
status ENUM('uploading','active','deleted','expired') NOT NULL
size_bytes BIGINT UNSIGNED NOT NULL
chunk_size INT UNSIGNED NOT NULL
chunk_count INT UNSIGNED NOT NULL
type ENUM('file','paste') NOT NULL
delete_token_hash BINARY(32) NOT NULL
download_count INT UNSIGNED NOT NULL DEFAULT 0
max_downloads INT UNSIGNED DEFAULT NULL
last_access_at DATETIME NULL

Indexes:
INDEX idx_expires (expires_at)
INDEX idx_status_expires (status, expires_at)

Note: download_count and last_access_at are optional. If you want maximum privacy, omit them or update only with coarse granularity. If you implement “max downloads”, you need counters. With a privacy-first stance, I would keep download_count only if you truly need it; otherwise do not.

uploads

Optional but helpful for resumable uploads and integrity:
locator BINARY(24) PRIMARY KEY
upload_token_hash BINARY(32) NOT NULL
token_expires_at DATETIME NOT NULL
received_chunks INT UNSIGNED NOT NULL DEFAULT 0
updated_at DATETIME NOT NULL

You can also track a bitmap of received chunks, but for 100–500 chunks it may be easier to count files on disk during complete.

rate_limits_anon

bucket_id BINARY(32) PRIMARY KEY
window_start DATETIME NOT NULL
count INT UNSIGNED NOT NULL
updated_at DATETIME NOT NULL

Where bucket_id is derived from a HttpOnly cookie token, for example HMAC(server_secret, cookie_value) so you never store the raw cookie.

rate_limits_user

user_id BIGINT UNSIGNED PRIMARY KEY
window_start DATETIME NOT NULL
count INT UNSIGNED NOT NULL
updated_at DATETIME NOT NULL

## 6) Rate limiting design under your constraints (2 uploads/hour anon)
Anonymous clearnet

Issue a Secure; HttpOnly; SameSite=Strict cookie anon_id that is a random 32-byte value Base64URL encoded. This is not identity; it is a per-browser bucket. Rotate it, for example every 24 hours, by setting a short expiry and renewing.

Bucket key: bucket_id = SHA-256(anon_id || server_secret) (store as BINARY(32)).

At POST /api/share/init, increment the counter for the current hour window; if count >= 2, reject.

If the user clears cookies, they can bypass. That is acceptable for privacy; you should then rely on PoW and edge throttling as additional control.

Tor/I2P

Cookies are less reliable and IP controls are inappropriate. Require PoW for anonymous uploads. The server returns a challenge and target difficulty; the browser computes a nonce such that SHA-256(challenge || nonce) has N leading zero bits. You verify quickly.

Difficulty can be modest (a few hundred milliseconds on a modern CPU) and increased if abuse spikes. You can still allow cookies on Tor, but do not rely on them.

Accounts

Tie to account ID and give higher limits. Because you are increasing retention to 14 days, you should treat “long retention” as an account-only privilege; for anonymous users, consider capping override to something smaller (for example 24 hours). If you insist anonymous can use 14 days, you should expect sustained abuse pressure, and you will need heavier PoW, tighter bandwidth caps, and more aggressive deletion policies.

## 7) PHP API endpoints (SPA backend contract)

Even as a single-page site, you will need a small REST-ish API. Suggested endpoints:

POST /api/share/init
Input: type, size_bytes, chunk_size, requested_expires_at, pow_solution (if required)
Server actions: validate limits (size, retention policy), enforce rate limit, create DB row with status uploading, compute storage path, generate short-lived upload_token (random 32 bytes) and store hash in uploads, return locator and upload_token and effective_expires_at.

PUT /api/share/{locator}/chunk/{i}
Headers: Authorization: Bearer <upload_token>
Body: ciphertext bytes
Server actions: validate token, validate chunk index and size, write file atomically, optionally track received count.

PUT /api/share/{locator}/manifest
Same auth as above
Body: manifest ciphertext bytes
Server actions: store manifest.bin.

POST /api/share/{locator}/complete
Server actions: verify manifest exists, verify chunk count present, switch status to active, delete upload token record.

GET /api/share/{locator}/manifest
Returns ciphertext manifest.bin if share active and not expired.

GET /api/share/{locator}/chunk/{i}
Returns ciphertext chunk.

POST /api/share/{locator}/delete
Input: delete_token (raw bytes Base64URL)
Server verifies SHA-256(delete_token) equals stored delete_token_hash in constant-time, deletes files and marks share deleted.

All GET endpoints should enforce expiry at request time; if expired, mark status expired and delete files best-effort before returning 404.

## 8) Retention policy logic with 14-day override

Define:
Default: 6 hours.
Maximum override: 14 days.
Enforce: expires_at = min(requested, now + 14 days).

Now the practical policy question is who is allowed to use the maximum. If you allow anonymous users to set 14 days, this becomes a durable file drop service for anyone, which is likely to attract sustained abuse. If you want to keep the service online while staying privacy-first, a common pattern is: anonymous maximum is small (for example 6–24 hours), authenticated maximum is 14 days. This does not require invasive identity if you use passkeys, and it provides an operational lever.

If you choose not to differentiate, then your anti-abuse controls must become more aggressive on anonymous: higher PoW, tighter bandwidth caps, and stricter filetype handling (though filetype handling often requires inspection, which conflicts with privacy). The cleanest lever remains retention differentiation.

## 9) Single-page security headers and delivery constraints

Because the SPA is security-critical, deploy it as static immutable assets with a strict CSP.

Recommended headers (high-level intent):
CSP that allows scripts only from self, disallows inline, disallows eval, locks down connect-src to your API origins only, disallows framing, and blocks object/embed.
Referrer-Policy: no-referrer to avoid leaking locators in referrers.
X-Content-Type-Options: nosniff
Permissions-Policy to disable unnecessary sensors and APIs.
Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Resource-Policy: same-origin as appropriate.

Ensure there are no third-party resources whatsoever, including fonts. On Tor/I2P, avoid any clearnet calls or absolute URL mistakes.

## 10) Client-side implementation notes (WebCrypto in the SPA)

The SPA must:
Generate random locator, salts, key seed, delete seed.
Derive enc_key with HKDF or directly import as AES-GCM key.
Chunk and encrypt using AES-GCM with derived per-chunk nonces.
Create and encrypt manifest.
Upload via init → chunk PUTs → manifest PUT → complete.
For retrieval: parse location.hash, extract locator and key material, fetch manifest and chunks, decrypt, reassemble, and offer download or display paste.

The SPA must never send the key material to the server. Be careful that you do not accidentally include the hash fragment in telemetry, errors, or any redirect.

## 11) Expiry and deletion: scheduled job

Implement a cron job, for example every 5 minutes:
Select shares with expires_at < now() and status in (uploading,active) and mark expired, then delete their directory on disk. For robustness, keep deletion idempotent. If the delete fails, keep a retry queue.

Given 14 days retention, storage will grow. You should enforce a global storage quota and refuse new uploads when the system approaches capacity; privacy-first does not mean “no operational controls”.

## 12) Where this design is intentionally strict

You are not scanning content. You are not doing server-side previews. You are not storing filenames or MIME types in plaintext. You are not logging IPs or user agents in application logs. You are keeping the server ignorant of the keys. Those decisions are what make this “extremely privacy focused”.

The trade-off is that you must invest in front-end integrity and anti-abuse controls, because you will not have content visibility as a safety valve.
