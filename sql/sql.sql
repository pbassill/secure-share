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

CREATE TABLE IF NOT EXISTS pow_challenges (
  challenge_id      BINARY(16) PRIMARY KEY,
  challenge_hash    BINARY(32) NOT NULL,
  difficulty_bits   INT UNSIGNED NOT NULL,
  expires_at        DATETIME NOT NULL,
  created_at        DATETIME NOT NULL
) ENGINE=InnoDB;

CREATE INDEX idx_pow_expires ON pow_challenges (expires_at);

CREATE TABLE IF NOT EXISTS users (
  id          BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  handle      VARBINARY(32) NOT NULL,         -- random user handle, not email
  created_at  DATETIME NOT NULL
) ENGINE=InnoDB;

CREATE UNIQUE INDEX ux_users_handle ON users (handle);

CREATE TABLE IF NOT EXISTS user_webauthn_credentials (
  id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id           BIGINT UNSIGNED NOT NULL,
  credential_id     VARBINARY(255) NOT NULL,
  public_key_cbor   BLOB NOT NULL,
  sign_count        INT UNSIGNED NOT NULL DEFAULT 0,
  created_at        DATETIME NOT NULL,
  UNIQUE KEY ux_cred (credential_id),
  INDEX idx_user (user_id),
  CONSTRAINT fk_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

