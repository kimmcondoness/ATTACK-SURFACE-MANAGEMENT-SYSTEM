-- Attack Surface Management System - MySQL 


CREATE DATABASE IF NOT EXISTS asm_system
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE asm_system;

SET FOREIGN_KEY_CHECKS = 0;

DROP TABLE IF EXISTS report_shares;
DROP TABLE IF EXISTS monitor_heartbeat;
DROP TABLE IF EXISTS monitor_runs;
DROP TABLE IF EXISTS monitor_events;
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
  last_seen_at    DATETIME     NULL,   -- last request; lets a sign-in say what monitoring did meanwhile
  UNIQUE KEY uq_users_username (username),
  UNIQUE KEY uq_users_email (email),
  CONSTRAINT chk_users_role CHECK (role IN ('it_admin', 'cybersecurity_analyst', 'threat_intel_analyst'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- authorized_targets

CREATE TABLE authorized_targets (
  id           INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  domain       VARCHAR(255) NOT NULL,
  description  VARCHAR(255) NULL,
  authorized   TINYINT(1)   NOT NULL DEFAULT 0,
  owner_id     INT UNSIGNED NOT NULL,
  created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  monitor_interval_days  INT      NULL,   -- continuous monitoring: re-scan every N days (NULL = off)
  monitor_last_run_at    DATETIME NULL,    -- when the last scan chain started
  monitor_set_by         INT UNSIGNED NULL,  -- the user who turned monitoring on (or last changed its schedule)
  monitor_set_at         DATETIME NULL,
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
  last_seen_at    DATETIME     NULL,                     -- when discovery last returned this host
  status          VARCHAR(20)  NOT NULL DEFAULT 'active', -- 'active' or 'missing'
  missed_runs     INT          NOT NULL DEFAULT 0,        -- discovery runs in a row that missed it
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


-- scans

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
  CONSTRAINT chk_scans_type CHECK (scan_type IN ('asset_discovery', 'port_discovery', 'vulnerability_scan', 'dork_scan')),
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

-- monitor_events: what continuous monitoring noticed changing between scans

CREATE TABLE monitor_events (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target_id   INT UNSIGNED NOT NULL,
  event_type  VARCHAR(30)  NOT NULL,   -- asset_new, asset_missing, asset_back, finding_new, finding_resolved, finding_reopened
  subject     VARCHAR(255) NOT NULL,
  severity    VARCHAR(20)  NULL,
  detail      TEXT         NULL,
  created_at  DATETIME     NULL DEFAULT CURRENT_TIMESTAMP,
  KEY ix_monitor_events_target_id (target_id),
  KEY ix_monitor_events_created_at (created_at),
  CONSTRAINT fk_events_target FOREIGN KEY (target_id) REFERENCES authorized_targets (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- monitor_runs: every scan chain that counts as monitoring (scheduled, or run by hand on a monitored
-- target). Written by the scheduler, so it records monitoring happening whether or not anyone is signed in.
-- No foreign keys on purpose: see the note in models.py (signed vs unsigned ids).

CREATE TABLE monitor_runs (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  target_id     INT UNSIGNED NOT NULL,
  lead_scan_id  INT UNSIGNED NULL,
  `trigger`     VARCHAR(10)  NOT NULL DEFAULT 'scheduled',   -- scheduled, manual
  status        VARCHAR(20)  NOT NULL DEFAULT 'running',     -- running, completed, failed, stopped, interrupted
  started_at    DATETIME     NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at   DATETIME     NULL,
  changes       INT          NOT NULL DEFAULT 0,
  alert_sent    TINYINT(1)   NOT NULL DEFAULT 0,
  summary       TEXT         NULL,
  KEY ix_monitor_runs_target_id (target_id),
  KEY ix_monitor_runs_lead_scan_id (lead_scan_id),
  KEY ix_monitor_runs_started_at (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- monitor_heartbeat: the scheduler's pulse (a single row, id 1, rewritten on every check)

CREATE TABLE monitor_heartbeat (
  id            INT PRIMARY KEY,
  started_at    DATETIME     NULL,
  last_tick_at  DATETIME     NULL,
  pid           INT          NULL,
  last_error    VARCHAR(255) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- report_shares: reports an analyst has shared with Threat Intelligence (each report at most once)

CREATE TABLE report_shares (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  report_id   INT UNSIGNED NOT NULL,
  shared_by   INT UNSIGNED NOT NULL,
  note        VARCHAR(500) NULL,
  shared_at   DATETIME     NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uq_report_shares_report_id (report_id),
  KEY ix_report_shares_shared_at (shared_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
