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

    // Anonymous enforcement (account logic can be added later)
    $isAuthed = false; // Replace with session check when accounts exist
    if (!$isAuthed) {
        if ($size > (int)$config['anon_max_bytes']) {
            json_response(['error' => 'Anonymous uploads limited to 100MB'], 403);
        }
        enforce_anon_rate_limit($pdo, $config);
    }

    $requestedExpires = null;
    if (isset($data['expires_at_epoch'])) {
        $requestedExpires = (int)$data['expires_at_epoch'];
    }
    $expiresEpoch = clamp_expires($config, $requestedExpires);
    $expiresAt = gmdate('Y-m-d H:i:s', $expiresEpoch);

    $locator = random_bytes(24);

    // Delete token hash is provided by client? Prefer server-side storage of hash only.
    // Here we accept a client-provided delete_token_hash (base64url of 32 bytes).
    $dth = $data['delete_token_hash_b64u'] ?? '';
    $dthBin = b64url_decode((string)$dth);
    if ($dthBin === '' || strlen($dthBin) !== 32) {
        json_response(['error' => 'Invalid delete token hash'], 400);
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
        'locator_hex' => locator_hex($locator),
        'upload_token' => $uploadToken,
        'expires_at_epoch' => $expiresEpoch,
        'chunk_size' => $chunkSize,
        'chunk_count' => $chunkCount,
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
