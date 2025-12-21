<?php
declare(strict_types=1);

require __DIR__ . '/../app/bootstrap.php';
require __DIR__ . '/../app/db.php';
require __DIR__ . '/../app/storage.php';
require __DIR__ . '/../app/rate_limit.php';
require __DIR__ . '/../app/webauthn.php';
require __DIR__ . '/../app/api.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$pdo = db($config);

$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// Basic security headers for all responses
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');
header('Cache-Control: no-store');

if (str_starts_with($uri, '/api/')) {

    if ($uri === '/api/pow/challenge') {
        api_pow_challenge($pdo, $config);
    }

    if ($uri === '/api/share/init') {
        api_share_init($pdo, $config);
    }

    if ($uri === '/api/auth/register/options') api_auth_register_options($pdo, $config);
    if ($uri === '/api/auth/register/verify') api_auth_register_verify($pdo, $config);
    if ($uri === '/api/auth/login/options') api_auth_login_options($pdo, $config);
    if ($uri === '/api/auth/login/verify') api_auth_login_verify($pdo, $config);
    if ($uri === '/api/auth/logout') api_auth_logout();

    $parts = explode('/', trim($uri, '/'));

    // /api/share/{locator}/chunk/{i}
    if (count($parts) === 5 && $parts[1] === 'share' && $parts[3] === 'chunk') {
        if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
            api_put_chunk($pdo, $config, $parts[2], (int)$parts[4]);
        }
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            api_get_chunk($pdo, $config, $parts[2], (int)$parts[4]);
        }
    }

    // /api/share/{locator}/manifest
    if (count($parts) === 4 && $parts[1] === 'share' && $parts[3] === 'manifest') {
        if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
            api_put_manifest($pdo, $config, $parts[2]);
        }
        if ($_SERVER['REQUEST_METHOD'] === 'GET') {
            api_get_manifest($pdo, $config, $parts[2]);
        }
    }

    // /api/share/{locator}/complete
    if (count($parts) === 4 && $parts[1] === 'share' && $parts[3] === 'complete') {
        api_complete($pdo, $config, $parts[2]);
    }

    // /api/share/{locator}/delete
    if (count($parts) === 4 && $parts[1] === 'share' && $parts[3] === 'delete') {
        api_delete($pdo, $config, $parts[2]);
    }

    json_response(['error' => 'Not found'], 404);
}

// Single-page app HTML
$csp = "default-src 'none'; "
     . "base-uri 'none'; "
     . "form-action 'none'; "
     . "frame-ancestors 'none'; "
     . "img-src 'self'; "
     . "style-src 'self'; "
     . "script-src 'self'; "
     . "connect-src 'self'; "
     . "font-src 'self'; "
     . "object-src 'none'; "
     . "media-src 'none'; ";

header("Content-Security-Policy: {$csp}");
header('Content-Type: text/html; charset=utf-8');

?><!doctype html>
<html lang="en-GB">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Secure Share</title>
  <link rel="stylesheet" href="/assets/app.css" />
</head>
<body>
  <div id="app"></div>
  <script src="/assets/app.js"></script>
</body>
</html>
