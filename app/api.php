<?php
declare(strict_types=1);

function parse_locator_from_path(string $hex): string {
    $hex = strtolower($hex);
    if (!preg_match('/^[0-9a-f]{48}$/', $hex)) { // 24 bytes
        json_response(['error' => 'Invalid locator'], 400);
    }
    $bin = hex2bin($hex);
    if ($bin === false || strlen($bin) !== 24) {
        json_response(['error' => 'Invalid locator'], 400);
    }
    return $bin;
}

function require_bearer_token(): string {
    $h = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/i', $h, $m)) {
        json_response(['error' => 'Missing upload token'], 401);
    }
    return trim($m[1]);
}

function clamp_expires(array $config, ?int $requested_epoch): int {
    $now = time();
    $default = $now + (int)$config['default_retention_seconds'];
    $max = $now + (int)$config['max_retention_seconds'];

    if ($requested_epoch === null) return $default;
    if ($requested_epoch < $now + 60) return $now + 60; // minimum 1 minute
    return min($requested_epoch, $max);
}

function is_authenticated(): bool {
    // Minimal session check. Replace later with WebAuthn session logic.
    return !empty($_SESSION['user_id']);
}

function api_share_init(PDO $pdo, array $config): never {
    require_method('POST');

    $body = get_raw_body();
    $data = json_decode($body, true);
    if (!is_array($data)) json_response(['error' => 'Invalid JSON'], 400);

    $type = $data['type'] ?? '';
    if (!in_array($type, ['file','paste'], true)) json_response(['error' => 'Invalid type'], 400);

    $size = (int)($data['size_bytes'] ?? 0);
    if ($size <= 0) json_response(['error' => 'Invalid size'], 400);

    $chunkSize = (int)($data['chunk_size'] ?? (1024 * 1024));
    if ($chunkSize < (int)$config['min_chunk_size'] || $chunkSize > (int)$config['max_chunk_size']) {
        json_response(['error' => 'Invalid chunk size'], 400);
    }

    $chunkCount = (int)ceil($size / $chunkSize);
    if ($chunkCount <= 0 || $chunkCount > (int)$config['max_chunk_count']) {
        json_response(['error' => 'Invalid chunk count'], 400);
    }

    // Client-supplied locator
    $locatorHex = strtolower((string)($data['locator_hex'] ?? ''));
    if (!preg_match('/^[0-9a-f]{48}$/', $locatorHex)) {
        json_response(['error' => 'Invalid locator'], 400);
    }
    $locator = hex2bin($locatorHex);
    if ($locator === false || strlen($locator) !== 24) {
        json_response(['error' => 'Invalid locator'], 400);
    }

    // Delete token hash (SHA-256(delete_token)) computed client-side
    $dth = (string)($data['delete_token_hash_b64u'] ?? '');
    $dthBin = b64url_decode($dth);
    if ($dthBin === '' || strlen($dthBin) !== 32) {
        json_response(['error' => 'Invalid delete token hash'], 400);
    }

    // Policy enforcement
    $authed = is_authenticated();

    if (!$authed) {
        if ($size > (int)$config['anon_max_bytes']) {
            json_response(['error' => 'Anonymous uploads limited to 100MB'], 403);
        }
        // Anonymous retention is capped at 6 hours (no override)
        $maxAnon = time() + (int)$config['default_retention_seconds'];
        $requested = isset($data['expires_at_epoch']) ? (int)$data['expires_at_epoch'] : 0;
        $expiresEpoch = $maxAnon;
        if ($requested > 0) {
            $expiresEpoch = min($requested, $maxAnon);
        }
        // Enforce anon rate limit (clearnet cookie bucket)
        enforce_anon_rate_limit($pdo, $config);

        // PoW for Tor/I2P (optional but recommended). We enforce if the client indicates tor/i2p,
        // or if you choose to enforce universally for anonymous to reduce abuse.
        $network = (string)($data['network'] ?? 'clearnet'); // client hint: clearnet|tor|i2p
        if (in_array($network, ['tor','i2p'], true)) {
            verify_pow($pdo, $config, $data, $locator); // defined later
        }

        $expiresAt = gmdate('Y-m-d H:i:s', $expiresEpoch);

    } else {
        // Authenticated: allow override up to 14 days
        $requested = isset($data['expires_at_epoch']) ? (int)$data['expires_at_epoch'] : null;
        $expiresEpoch = clamp_expires($config, $requested);
        $expiresAt = gmdate('Y-m-d H:i:s', $expiresEpoch);
    }

    // Reject collisions: locator is the key
    $stmt = $pdo->prepare("SELECT 1 FROM shares WHERE locator = ?");
    $stmt->execute([$locator]);
    if ($stmt->fetch()) {
        json_response(['error' => 'Locator already exists'], 409);
    }

    $now = gmdate('Y-m-d H:i:s');
    $pdo->prepare("INSERT INTO shares (locator, created_at, expires_at, status, type, size_bytes, chunk_size, chunk_count, delete_token_hash)
                   VALUES (?, ?, ?, 'uploading', ?, ?, ?, ?, ?)")
        ->execute([$locator, $now, $expiresAt, $type, $size, $chunkSize, $chunkCount, $dthBin]);

    // Short-lived upload token
    $uploadToken = b64url_encode(random_bytes(32));
    $uploadTokenHash = hash('sha256', $uploadToken . $config['app_secret'], true);
    $tokenExp = gmdate('Y-m-d H:i:s', time() + (int)$config['upload_token_ttl_seconds']);

    $pdo->prepare("INSERT INTO uploads (locator, upload_token_hash, token_expires_at, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?)")
        ->execute([$locator, $uploadTokenHash, $tokenExp, $now, $now]);

    ensure_storage_dir($config, $locator);

    json_response([
        'locator_hex' => $locatorHex,
        'upload_token' => $uploadToken,
        'expires_at_epoch' => strtotime($expiresAt . ' UTC'),
        'chunk_size' => $chunkSize,
        'chunk_count' => $chunkCount,
        'authed' => $authed,
    ], 200);
}


function verify_upload_token(PDO $pdo, array $config, string $locator, string $token): void {
    $tokenHash = hash('sha256', $token . $config['app_secret'], true);
    $stmt = $pdo->prepare("SELECT upload_token_hash, token_expires_at FROM uploads WHERE locator = ?");
    $stmt->execute([$locator]);
    $row = $stmt->fetch();
    if (!$row) json_response(['error' => 'Upload not authorised'], 401);

    if (!timing_safe_equals($row['upload_token_hash'], $tokenHash)) {
        json_response(['error' => 'Upload not authorised'], 401);
    }
    if (strtotime($row['token_expires_at'] . ' UTC') < time()) {
        json_response(['error' => 'Upload token expired'], 401);
    }
}

function require_active_share(PDO $pdo, string $locator): array {
    $stmt = $pdo->prepare("SELECT * FROM shares WHERE locator = ?");
    $stmt->execute([$locator]);
    $row = $stmt->fetch();
    if (!$row) json_response(['error' => 'Not found'], 404);

    $expires = strtotime($row['expires_at'] . ' UTC');
    if ($row['status'] === 'deleted' || $row['status'] === 'expired' || $expires < time()) {
        json_response(['error' => 'Not found'], 404);
    }
    return $row;
}

function api_put_chunk(PDO $pdo, array $config, string $locatorHex, int $index): never {
    require_method('PUT');
    $locator = parse_locator_from_path($locatorHex);

    $token = require_bearer_token();
    verify_upload_token($pdo, $config, $locator, $token);

    $share = require_active_share($pdo, $locator);
    if ($share['status'] !== 'uploading') json_response(['error' => 'Invalid state'], 409);

    $maxIndex = (int)$share['chunk_count'] - 1;
    if ($index < 0 || $index > $maxIndex) json_response(['error' => 'Invalid chunk index'], 400);

    $data = get_raw_body();
    $len = strlen($data);
    if ($len <= 0) json_response(['error' => 'Empty chunk'], 400);

    // Defensive bound: chunk can be up to chunk_size + overhead (GCM tag etc.)
    $chunkSize = (int)$share['chunk_size'];
    if ($len > $chunkSize + 64) {
        json_response(['error' => 'Chunk too large'], 413);
    }

    $path = chunk_path($config, $locator, $index);
    atomic_write($path, $data);

    $pdo->prepare("UPDATE uploads SET updated_at = ? WHERE locator = ?")
        ->execute([gmdate('Y-m-d H:i:s'), $locator]);

    json_response(['ok' => true], 200);
}

function api_put_manifest(PDO $pdo, array $config, string $locatorHex): never {
    require_method('PUT');
    $locator = parse_locator_from_path($locatorHex);

    $token = require_bearer_token();
    verify_upload_token($pdo, $config, $locator, $token);

    $share = require_active_share($pdo, $locator);
    if ($share['status'] !== 'uploading') json_response(['error' => 'Invalid state'], 409);

    $data = get_raw_body();
    if (strlen($data) <= 0 || strlen($data) > 5 * 1024 * 1024) {
        json_response(['error' => 'Invalid manifest size'], 400);
    }

    $path = manifest_path($config, $locator);
    atomic_write($path, $data);

    $pdo->prepare("UPDATE uploads SET updated_at = ? WHERE locator = ?")
        ->execute([gmdate('Y-m-d H:i:s'), $locator]);

    json_response(['ok' => true], 200);
}

function api_complete(PDO $pdo, array $config, string $locatorHex): never {
    require_method('POST');
    $locator = parse_locator_from_path($locatorHex);

    $token = require_bearer_token();
    verify_upload_token($pdo, $config, $locator, $token);

    $share = require_active_share($pdo, $locator);
    if ($share['status'] !== 'uploading') json_response(['error' => 'Invalid state'], 409);

    // Verify manifest exists
    $m = manifest_path($config, $locator);
    if (!is_file($m)) json_response(['error' => 'Manifest missing'], 400);

    // Verify chunks exist (best-effort; do not scan content)
    $count = (int)$share['chunk_count'];
    for ($i = 0; $i < $count; $i++) {
        $p = chunk_path($config, $locator, $i);
        if (!is_file($p)) json_response(['error' => 'Missing chunk', 'chunk' => $i], 400);
    }

    $pdo->prepare("UPDATE shares SET status = 'active' WHERE locator = ?")->execute([$locator]);
    $pdo->prepare("DELETE FROM uploads WHERE locator = ?")->execute([$locator]);

    json_response(['ok' => true], 200);
}

function api_get_manifest(PDO $pdo, array $config, string $locatorHex): never {
    require_method('GET');
    $locator = parse_locator_from_path($locatorHex);
    $share = require_active_share($pdo, $locator);

    if ($share['status'] !== 'active') json_response(['error' => 'Not found'], 404);

    // Optional: update last_access_at with coarse granularity if you want
    $pdo->prepare("UPDATE shares SET last_access_at = ? WHERE locator = ?")
        ->execute([gmdate('Y-m-d H:i:s'), $locator]);

    stream_file(manifest_path($config, $locator));
}

function api_get_chunk(PDO $pdo, array $config, string $locatorHex, int $index): never {
    require_method('GET');
    $locator = parse_locator_from_path($locatorHex);
    $share = require_active_share($pdo, $locator);

    if ($share['status'] !== 'active') json_response(['error' => 'Not found'], 404);
    $maxIndex = (int)$share['chunk_count'] - 1;
    if ($index < 0 || $index > $maxIndex) json_response(['error' => 'Invalid chunk index'], 400);

    stream_file(chunk_path($config, $locator, $index));
}

function api_delete(PDO $pdo, array $config, string $locatorHex): never {
    require_method('POST');
    $locator = parse_locator_from_path($locatorHex);

    $share = $pdo->prepare("SELECT delete_token_hash, status FROM shares WHERE locator = ?");
    $share->execute([$locator]);
    $row = $share->fetch();
    if (!$row) json_response(['error' => 'Not found'], 404);
    if ($row['status'] === 'deleted') json_response(['ok' => true], 200);

    $data = json_decode(get_raw_body(), true);
    if (!is_array($data)) json_response(['error' => 'Invalid JSON'], 400);

    $tokenB64u = (string)($data['delete_token_b64u'] ?? '');
    $token = b64url_decode($tokenB64u);
    if ($token === '' || strlen($token) !== 32) json_response(['error' => 'Invalid delete token'], 400);

    $tokenHash = hash('sha256', $token, true);
    if (!timing_safe_equals($row['delete_token_hash'], $tokenHash)) {
        json_response(['error' => 'Not authorised'], 403);
    }

    // Mark deleted first, then delete files.
    $pdo->prepare("UPDATE shares SET status='deleted' WHERE locator=?")->execute([$locator]);
    delete_share_files($config, $locator);

    json_response(['ok' => true], 200);
}

function leading_zero_bits(string $hash32): int {
    $bits = 0;
    for ($i = 0; $i < 32; $i++) {
        $byte = ord($hash32[$i]);
        if ($byte === 0) { $bits += 8; continue; }
        for ($b = 7; $b >= 0; $b--) {
            if (($byte & (1 << $b)) === 0) $bits++;
            else return $bits;
        }
    }
    return $bits;
}

function api_pow_challenge(PDO $pdo, array $config): never {
    require_method('GET');

    // Difficulty policy: tune as needed. 18–22 bits is typically sub-second to a few seconds in JS.
    // For tor/i2p you might start at 20 bits; if abuse rises, raise gradually.
    $difficulty = 20;

    $challengeId = random_bytes(16);
    $challenge = random_bytes(32);
    $challengeHash = hash('sha256', $challenge, true);

    $now = gmdate('Y-m-d H:i:s');
    $exp = gmdate('Y-m-d H:i:s', time() + 10 * 60); // 10 min validity

    $pdo->prepare("INSERT INTO pow_challenges (challenge_id, challenge_hash, difficulty_bits, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?)")
        ->execute([$challengeId, $challengeHash, $difficulty, $exp, $now]);

    json_response([
        'challenge_id_b64u' => b64url_encode($challengeId),
        'challenge_b64u' => b64url_encode($challenge),
        'difficulty_bits' => $difficulty,
        'expires_at_epoch' => strtotime($exp . ' UTC'),
    ], 200);
}

function verify_pow(PDO $pdo, array $config, array $data, string $locator): void {
    $cid = (string)($data['pow_challenge_id_b64u'] ?? '');
    $cbytes = (string)($data['pow_challenge_b64u'] ?? '');
    $nonceB64u = (string)($data['pow_nonce_b64u'] ?? '');

    $challengeId = b64url_decode($cid);
    $challenge = b64url_decode($cbytes);
    $nonce = b64url_decode($nonceB64u);

    if ($challengeId === '' || strlen($challengeId) !== 16) json_response(['error' => 'Invalid PoW challenge id'], 400);
    if ($challenge === '' || strlen($challenge) !== 32) json_response(['error' => 'Invalid PoW challenge'], 400);
    if ($nonce === '' || strlen($nonce) !== 8) json_response(['error' => 'Invalid PoW nonce'], 400);

    $stmt = $pdo->prepare("SELECT challenge_hash, difficulty_bits, expires_at FROM pow_challenges WHERE challenge_id = ?");
    $stmt->execute([$challengeId]);
    $row = $stmt->fetch();
    if (!$row) json_response(['error' => 'PoW challenge not found'], 400);

    if (strtotime($row['expires_at'] . ' UTC') < time()) {
        json_response(['error' => 'PoW challenge expired'], 400);
    }

    $expected = $row['challenge_hash'];
    $actual = hash('sha256', $challenge, true);
    if (!timing_safe_equals($expected, $actual)) {
        json_response(['error' => 'PoW challenge invalid'], 400);
    }

    $digest = hash('sha256', $challenge . $locator . $nonce, true);
    $lz = leading_zero_bits($digest);
    if ($lz < (int)$row['difficulty_bits']) {
        json_response(['error' => 'PoW failed'], 403);
    }

    // One-time use: delete challenge to prevent replay
    $pdo->prepare("DELETE FROM pow_challenges WHERE challenge_id = ?")->execute([$challengeId]);
}

function api_auth_register_options(PDO $pdo, array $config): never {
    require_method('GET');

    // Create a new user handle (random, non-identifying)
    $handle = random_bytes(32);
    $now = gmdate('Y-m-d H:i:s');
    $pdo->prepare("INSERT INTO users (handle, created_at) VALUES (?, ?)")->execute([$handle, $now]);
    $userId = (int)$pdo->lastInsertId();

    // Store in session during registration
    $_SESSION['reg_user_id'] = $userId;

    // Create challenge and options; in production, use webauthn-lib to build this.
    $challenge = random_bytes(32);
    $_SESSION['reg_challenge'] = $challenge;

    json_response([
        'rp' => [
            'name' => 'Secure Share',
            'id' => $_SERVER['HTTP_HOST'],
        ],
        'user' => [
            'id_b64u' => b64url_encode($handle),
            'name' => 'user-' . $userId,
            'displayName' => 'Secure Share User',
        ],
        'challenge_b64u' => b64url_encode($challenge),
        'pubKeyCredParams' => [
            ['type' => 'public-key', 'alg' => -7],   // ES256
            ['type' => 'public-key', 'alg' => -257], // RS256
        ],
        'timeout' => 60000,
        'attestation' => 'none',
        'authenticatorSelection' => [
            'residentKey' => 'preferred',
            'userVerification' => 'preferred',
        ],
    ], 200);
}

function api_auth_register_verify(PDO $pdo, array $config): never {
    require_method('POST');
    $data = json_decode(get_raw_body(), true);
    if (!is_array($data)) json_response(['error' => 'Invalid JSON'], 400);

    $userId = (int)($_SESSION['reg_user_id'] ?? 0);
    $challenge = $_SESSION['reg_challenge'] ?? null;
    if ($userId <= 0 || !is_string($challenge) || strlen($challenge) !== 32) {
        json_response(['error' => 'No registration in progress'], 400);
    }

    // Here you must verify attestation using a WebAuthn library.
    // You need to extract: credentialId, publicKey (COSE/CBOR), signCount.
    // If verification succeeds, store in user_webauthn_credentials.

    // Placeholder expected fields from client:
    $credId = b64url_decode((string)($data['credential_id_b64u'] ?? ''));
    $pubKeyCbor = b64url_decode((string)($data['public_key_cbor_b64u'] ?? ''));
    $signCount = (int)($data['sign_count'] ?? 0);

    if ($credId === '' || $pubKeyCbor === '') json_response(['error' => 'Invalid credential data'], 400);

    $now = gmdate('Y-m-d H:i:s');
    $pdo->prepare("INSERT INTO user_webauthn_credentials (user_id, credential_id, public_key_cbor, sign_count, created_at)
                   VALUES (?, ?, ?, ?, ?)")
        ->execute([$userId, $credId, $pubKeyCbor, $signCount, $now]);

    unset($_SESSION['reg_user_id'], $_SESSION['reg_challenge']);

    // Mark authenticated
    $_SESSION['user_id'] = $userId;

    json_response(['ok' => true, 'user_id' => $userId], 200);
}

function api_auth_login_options(PDO $pdo, array $config): never {
    require_method('GET');

    // For privacy-first accounts without email, you need some way to select the user.
    // The most privacy-preserving approach is to use discoverable credentials (resident keys),
    // so you do not need a username. In that case, you can provide allowCredentials as empty.

    $challenge = random_bytes(32);
    $_SESSION['login_challenge'] = $challenge;

    json_response([
        'challenge_b64u' => b64url_encode($challenge),
        'timeout' => 60000,
        'userVerification' => 'preferred',
        'allowCredentials' => [], // discoverable credentials
    ], 200);
}

function api_auth_login_verify(PDO $pdo, array $config): never {
    require_method('POST');
    $data = json_decode(get_raw_body(), true);
    if (!is_array($data)) json_response(['error' => 'Invalid JSON'], 400);

    $challenge = $_SESSION['login_challenge'] ?? null;
    if (!is_string($challenge) || strlen($challenge) !== 32) {
        json_response(['error' => 'No login in progress'], 400);
    }

    // You must verify assertion with a WebAuthn library.
    // You will receive credentialId, authenticatorData, clientDataJSON, signature, userHandle (optional).
    // Use credentialId to look up public_key_cbor and user_id, verify signature, check and update sign_count.

    $credId = b64url_decode((string)($data['credential_id_b64u'] ?? ''));
    if ($credId === '') json_response(['error' => 'Invalid credential id'], 400);

    $stmt = $pdo->prepare("SELECT user_id, public_key_cbor, sign_count FROM user_webauthn_credentials WHERE credential_id = ?");
    $stmt->execute([$credId]);
    $row = $stmt->fetch();
    if (!$row) json_response(['error' => 'Unknown credential'], 403);

    $userId = (int)$row['user_id'];

    // Placeholder: you must verify using library, then update sign_count accordingly.
    // For now we accept and set the session (not secure until verification is implemented).
    $_SESSION['user_id'] = $userId;
    unset($_SESSION['login_challenge']);

    json_response(['ok' => true, 'user_id' => $userId], 200);
}

function api_auth_logout(): never {
    require_method('POST');
    session_destroy();
    json_response(['ok' => true], 200);
}
