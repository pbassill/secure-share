<?php
declare(strict_types=1);

$config = require __DIR__ . '/config.php';

date_default_timezone_set('UTC');

function json_response(array $data, int $status = 200): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function require_method(string $method): void {
    if ($_SERVER['REQUEST_METHOD'] !== $method) {
        json_response(['error' => 'Method Not Allowed'], 405);
    }
}

function get_raw_body(): string {
    $body = file_get_contents('php://input');
    return $body === false ? '' : $body;
}

function b64url_encode(string $bin): string {
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function b64url_decode(string $txt): string {
    $txt = strtr($txt, '-_', '+/');
    $pad = strlen($txt) % 4;
    if ($pad) $txt .= str_repeat('=', 4 - $pad);
    $bin = base64_decode($txt, true);
    return $bin === false ? '' : $bin;
}

function timing_safe_equals(string $a, string $b): bool {
    return hash_equals($a, $b);
}
