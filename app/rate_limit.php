<?php
declare(strict_types=1);

function anon_bucket_id(array $config): string {
    $cookieName = 'anon_id';
    if (empty($_COOKIE[$cookieName]) || strlen((string)$_COOKIE[$cookieName]) < 16) {
        $raw = random_bytes(32);
        $val = b64url_encode($raw);
        setcookie($cookieName, $val, [
            'expires' => time() + 86400, // 24h
            'path' => '/',
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        $_COOKIE[$cookieName] = $val;
    }
    $raw = b64url_decode((string)$_COOKIE[$cookieName]);
    if ($raw === '' || strlen($raw) < 16) {
        $raw = random_bytes(32);
    }
    return hash('sha256', $raw . $config['app_secret'], true);
}

function hour_window_start(): string {
    $t = time();
    $t = $t - ($t % 3600);
    return gmdate('Y-m-d H:i:s', $t);
}

function enforce_anon_rate_limit(PDO $pdo, array $config): void {
    $bucket = anon_bucket_id($config);
    $window = hour_window_start();
    $now = gmdate('Y-m-d H:i:s');

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("SELECT window_start, count FROM rate_limits_anon WHERE bucket_id = ? FOR UPDATE");
        $stmt->execute([$bucket]);
        $row = $stmt->fetch();

        if (!$row) {
            $ins = $pdo->prepare("INSERT INTO rate_limits_anon (bucket_id, window_start, count, updated_at) VALUES (?, ?, 1, ?)");
            $ins->execute([$bucket, $window, $now]);
            $pdo->commit();
            return;
        }

        if ($row['window_start'] !== $window) {
            $upd = $pdo->prepare("UPDATE rate_limits_anon SET window_start = ?, count = 1, updated_at = ? WHERE bucket_id = ?");
            $upd->execute([$window, $now, $bucket]);
            $pdo->commit();
            return;
        }

        $count = (int)$row['count'];
        if ($count >= (int)$config['anon_max_uploads_per_hour']) {
            $pdo->rollBack();
            json_response(['error' => 'Rate limit exceeded'], 429);
        }

        $upd = $pdo->prepare("UPDATE rate_limits_anon SET count = count + 1, updated_at = ? WHERE bucket_id = ?");
        $upd->execute([$now, $bucket]);
        $pdo->commit();
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) $pdo->rollBack();
        throw $e;
    }
}
