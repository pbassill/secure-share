<?php
declare(strict_types=1);

return [
    'db' => [
        'dsn'  => 'mysql:host=127.0.0.1;dbname=secure_share;charset=utf8mb4',
        'user' => 'secure_share_user',
        'pass' => 'REPLACE_ME',
        'options' => [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ],
    ],

    // Ensure this is a long, random secret (at least 32 bytes) and keep it out of git.
    'app_secret' => 'REPLACE_WITH_LONG_RANDOM_SECRET',

    // Disk storage root (must be outside web root).
    'storage_root' => '/var/lib/secure-share/storage',

    // Anonymous limits
    'anon_max_bytes' => 100 * 1024 * 1024,           // 100MB
    'anon_max_uploads_per_hour' => 2,

    // Retention policy
    'default_retention_seconds' => 6 * 3600,         // 6 hours
    'max_retention_seconds' => 14 * 24 * 3600,        // 14 days

    // Upload token expiry (short-lived)
    'upload_token_ttl_seconds' => 20 * 60,           // 20 minutes

    // Chunk sizing policy
    'min_chunk_size' => 256 * 1024,                  // 256KB
    'max_chunk_size' => 4 * 1024 * 1024,             // 4MB

    // Maximum chunks allowed (defensive)
    'max_chunk_count' => 100000,
];
