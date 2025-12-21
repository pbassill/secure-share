CREATE DATABASE IF NOT EXISTS secure_share
  DEFAULT CHARACTER SET utf8mb4
  DEFAULT COLLATE utf8mb4_unicode_ci;

USE secure_share;

CREATE TABLE IF NOT EXISTS shares (
  locator            BINARY(24) PRIMARY KEY,
  created_at         DATETIME NOT NULL,
  expires_at         DATETIME NOT NULL,
  status             ENUM('uploading','active','deleted','expired') NOT NULL DEFAULT 'uploading',
  type               ENUM('file','paste') NOT NULL,
  size_bytes         BIGINT UNSIGNED NOT NULL,
  chunk_size         INT UNSIGNED NOT NULL,
  chunk_count        INT UNSIGNED NOT NULL,
  delete_token_hash  BINARY(32) NOT NULL,
  last_access_at     DATETIME NULL
) ENGINE=InnoDB;

CREATE INDEX idx_shares_expires_at ON shares (expires_at);
CREATE INDEX idx_shares_status_expires ON shares (status, expires_at);

CREATE TABLE IF NOT EXISTS uploads (
  locator            BINARY(24) PRIMARY KEY,
  upload_token_hash  BINARY(32) NOT NULL,
  token_expires_at   DATETIME NOT NULL,
  created_at         DATETIME NOT NULL,
  updated_at         DATETIME NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_uploads_token_expires ON uploads (token_expires_at);

CREATE TABLE IF NOT EXISTS rate_limits_anon (
  bucket_id     BINARY(32) PRIMARY KEY,
  window_start  DATETIME NOT NULL,
  count         INT UNSIGNED NOT NULL,
  updated_at    DATETIME NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_rate_limits_anon_window ON rate_limits_anon (window_start);

CREATE TABLE IF NOT EXISTS rate_limits_user (
  user_id       BIGINT UNSIGNED PRIMARY KEY,
  window_start  DATETIME NOT NULL,
  count         INT UNSIGNED NOT NULL,
  updated_at    DATETIME NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_rate_limits_user_window ON rate_limits_user (window_start);
