-- Attack Surface Management System - MySQL schema


CREATE DATABASE IF NOT EXISTS asm_system
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE asm_system;

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS reports;
DROP TABLE IF EXISTS scans;
DROP TABLE IF EXISTS vulnerabilities;
DROP TABLE IF EXISTS ports_services;
DROP TABLE IF EXISTS assets;
DROP TABLE IF EXISTS authorized_targets;
DROP TABLE IF EXISTS users;

SET FOREIGN_KEY_CHECKS = 1;

-- USERS LIST

CREATE TABLE users (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username        VARCHAR(80)  NOT NULL,
  email           VARCHAR(120) NOT NULL,
  first_name      VARCHAR(80)  NULL,
  last_name       VARCHAR(80)  NULL,
  password_hash   VARCHAR(128) NOT NULL,
  role            VARCHAR(30)  NOT NULL DEFAULT 'cybersecurity_analyst',
  is_active_flag  TINYINT(1)   NOT NULL DEFAULT 1,
  created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_users_username (username),
  UNIQUE KEY uq_users_email (email),
  CONSTRAINT chk_users_role CHECK (role IN ('it_admin', 'cybersecurity_analyst', 'security_team', 'threat_intel_analyst'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- authorized_targets

CREATE TABLE authorized_targets (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain       VARCHAR(255) NOT NULL,
  description  VARCHAR(255) NULL,
  authorized   TINYINT(1)   NOT NULL DEFAULT 0,
  owner_id     INT UNSIGNED NOT NULL,
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_authorized_targets_owner_id (owner_id),
  CONSTRAINT fk_targets_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- assets

CREATE TABLE assets (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target_id       INT UNSIGNED NOT NULL,
  subdomain       VARCHAR(255) NULL,
  ip_address      VARCHAR(45)  NULL,
  url             VARCHAR(500) NULL,
  technologies    VARCHAR(500) NULL,
  discovery_date  DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_assets_target_id (target_id),
  CONSTRAINT fk_assets_target FOREIGN KEY (target_id) REFERENCES authorized_targets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ports_services

CREATE TABLE ports_services (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  asset_id          INT UNSIGNED NOT NULL,
  port              INT UNSIGNED NOT NULL,
  protocol          VARCHAR(10)  NOT NULL DEFAULT 'tcp',
  service_name      VARCHAR(100) NULL,
  service_version   VARCHAR(100) NULL,
  state             VARCHAR(20)  NOT NULL DEFAULT 'open',
  discovered_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_ports_services_asset_id (asset_id),
  CONSTRAINT fk_ports_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- vulnerabilities

CREATE TABLE vulnerabilities (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  asset_id        INT UNSIGNED NOT NULL,
  severity        VARCHAR(20)  NOT NULL,
  cve             VARCHAR(50)  NULL,
  title           VARCHAR(255) NOT NULL,
  description     TEXT NULL,
  recommendation  TEXT NULL,
  status          VARCHAR(20)  NOT NULL DEFAULT 'open',
  discovered_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  cvss_score      FLOAT        NULL,
  kev             TINYINT(1)   NOT NULL DEFAULT 0,
  exploit_available TINYINT(1) NOT NULL DEFAULT 0,
  KEY ix_vulnerabilities_asset_id (asset_id),
  CONSTRAINT fk_vulns_asset FOREIGN KEY (asset_id) REFERENCES assets (id) ON DELETE CASCADE,
  CONSTRAINT chk_vulns_severity CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  CONSTRAINT chk_vulns_status CHECK (status IN ('open', 'in_progress', 'resolved', 'false_positive'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- scans
-- ---------------------------------------------------------------------------
CREATE TABLE scans (
  id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target_id       INT UNSIGNED NOT NULL,
  scan_type       VARCHAR(30)  NOT NULL,
  status          VARCHAR(20)  NOT NULL DEFAULT 'pending',
  started_by      INT UNSIGNED NOT NULL,
  started_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at    DATETIME     NULL,
  result_summary  TEXT NULL,
  source          VARCHAR(10)  NOT NULL DEFAULT 'mock',
  KEY ix_scans_target_id (target_id),
  KEY ix_scans_started_by (started_by),
  CONSTRAINT fk_scans_target FOREIGN KEY (target_id) REFERENCES authorized_targets (id) ON DELETE CASCADE,
  CONSTRAINT fk_scans_user FOREIGN KEY (started_by) REFERENCES users (id),
  CONSTRAINT chk_scans_type CHECK (scan_type IN ('asset_discovery', 'port_discovery', 'vulnerability_scan')),
  CONSTRAINT chk_scans_status CHECK (status IN ('pending', 'running', 'paused', 'completed', 'failed', 'stopped'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- reports

CREATE TABLE reports (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target_id      INT UNSIGNED NOT NULL,
  report_type    VARCHAR(10)  NOT NULL,
  file_path      VARCHAR(500) NOT NULL,
  generated_by   INT UNSIGNED NOT NULL,
  generated_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_reports_target_id (target_id),
  KEY ix_reports_generated_by (generated_by),
  CONSTRAINT fk_reports_target FOREIGN KEY (target_id) REFERENCES authorized_targets (id) ON DELETE CASCADE,
  CONSTRAINT fk_reports_user FOREIGN KEY (generated_by) REFERENCES users (id),
  CONSTRAINT chk_reports_type CHECK (report_type IN ('pdf', 'csv'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- audit_logs

CREATE TABLE audit_logs (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id     INT UNSIGNED NULL,
  action      VARCHAR(100) NOT NULL,
  detail      TEXT NULL,
  timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_audit_logs_user_id (user_id),
  CONSTRAINT fk_audit_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------------
-- seed data: default IT Admin account (username: admin / password: ChangeMe123!)
-- Change this password immediately after first login.
-- ---------------------------------------------------------------------------
INSERT INTO users (username, email, first_name, last_name, password_hash, role, is_active_flag)
VALUES (
  'admin',
  'admin@example.com',
  'System',
  'Admin',
  '$2b$12$lm/rsYvVh4PInugrbSxmkeTRIJpy4OsS.U.7nOGxFDIbX7aYfnrEa',
  'it_admin',
  1
);
