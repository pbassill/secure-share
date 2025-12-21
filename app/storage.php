<?php
declare(strict_types=1);

function locator_hex(string $locator_bin): string {
    return bin2hex($locator_bin);
}

function storage_dir(array $config, string $locator_bin): string {
    $hex = locator_hex($locator_bin);
    $prefix = substr($hex, 0, 4);
    return rtrim($config['storage_root'], '/') . '/' . $prefix . '/' . $hex;
}

function ensure_storage_dir(array $config, string $locator_bin): string {
    $dir = storage_dir($config, $locator_bin);
    if (!is_dir($dir)) {
        if (!mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException('Failed to create storage directory');
        }
    }
    return $dir;
}

function chunk_path(array $config, string $locator_bin, int $index): string {
    $dir = storage_dir($config, $locator_bin);
    return $dir . '/chunk_' . str_pad((string)$index, 6, '0', STR_PAD_LEFT) . '.bin';
}

function manifest_path(array $config, string $locator_bin): string {
    $dir = storage_dir($config, $locator_bin);
    return $dir . '/manifest.bin';
}

function atomic_write(string $path, string $data): void {
    $tmp = $path . '.tmp.' . bin2hex(random_bytes(8));
    $bytes = file_put_contents($tmp, $data, LOCK_EX);
    if ($bytes === false || $bytes !== strlen($data)) {
        @unlink($tmp);
        throw new RuntimeException('Failed to write file');
    }
    if (!rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException('Failed to move file into place');
    }
    @chmod($path, 0600);
}

function stream_file(string $path): never {
    if (!is_file($path)) {
        http_response_code(404);
        header('Cache-Control: no-store');
        exit;
    }
    header('Content-Type: application/octet-stream');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');

    $fp = fopen($path, 'rb');
    if ($fp === false) {
        http_response_code(500);
        exit;
    }
    fpassthru($fp);
    fclose($fp);
    exit;
}

function delete_share_files(array $config, string $locator_bin): void {
    $dir = storage_dir($config, $locator_bin);
    if (!is_dir($dir)) return;

    $it = new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS);
    $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($files as $file) {
        /** @var SplFileInfo $file */
        if ($file->isDir()) {
            @rmdir($file->getPathname());
        } else {
            @unlink($file->getPathname());
        }
    }
    @rmdir($dir);
}
