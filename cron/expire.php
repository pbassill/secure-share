<?php
declare(strict_types=1);

require __DIR__ . '/../app/bootstrap.php';
require __DIR__ . '/../app/db.php';
require __DIR__ . '/../app/storage.php';

$pdo = db($config);
$now = gmdate('Y-m-d H:i:s');

// Expire active or uploading shares
$stmt = $pdo->prepare("SELECT locator FROM shares WHERE status IN ('uploading','active') AND expires_at < ?");
$stmt->execute([$now]);
$rows = $stmt->fetchAll();

foreach ($rows as $r) {
    $locator = $r['locator'];
    // Mark expired first (idempotent)
    $pdo->prepare("UPDATE shares SET status='expired' WHERE locator=?")->execute([$locator]);
    $pdo->prepare("DELETE FROM uploads WHERE locator=?")->execute([$locator]);
    delete_share_files($config, $locator);
}

// Also clear expired upload tokens
$pdo->prepare("DELETE FROM uploads WHERE token_expires_at < ?")->execute([$now]);
$pdo->prepare("DELETE FROM pow_challenges WHERE expires_at < ?")->execute([$now]);

