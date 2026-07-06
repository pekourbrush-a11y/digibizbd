-- =====================================================================
-- database.sql
-- ---------------------------------------------------------------------
-- Core backend foundation schema — infrastructure tables only.
-- Target: MySQL 5.7+ / MariaDB 10.3+ (cPanel default)
-- Engine: InnoDB | Charset: utf8mb4
--
-- SCOPE: No users/authentication tables are included here, per the
-- "Do NOT create Authentication" requirement. When you build your
-- Authentication module later, add a `users` table and then attach
-- proper foreign keys from activity_logs.actor_id and
-- notifications.recipient_id to users.id.
--
-- Import via phpMyAdmin, or:
--   mysql -u your_db_user -p your_database_name < database.sql
-- =====================================================================

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ---------------------------------------------------------------------
-- Table: settings
-- Global key/value application settings.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `settings` (
    `id`             INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `setting_key`    VARCHAR(100) NOT NULL,
    `setting_value`  TEXT NULL DEFAULT NULL,
    `updated_at`     DATETIME NULL DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uq_settings_key` (`setting_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Table: activity_logs
-- General audit trail ("what happened, when"). `actor_id` is a plain
-- nullable integer — NOT a foreign key — since no users table exists
-- in this foundation yet.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `activity_logs` (
    `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `actor_id`      INT UNSIGNED NULL DEFAULT NULL COMMENT 'Link to users.id once auth exists',
    `action`        VARCHAR(100) NOT NULL COMMENT 'e.g. updated_settings, created_record',
    `description`   TEXT NULL DEFAULT NULL,
    `subject_type`  VARCHAR(100) NULL DEFAULT NULL COMMENT 'e.g. Setting, Notification',
    `subject_id`    INT UNSIGNED NULL DEFAULT NULL,
    `ip_address`    VARCHAR(45) NULL DEFAULT NULL,
    `user_agent`    VARCHAR(255) NULL DEFAULT NULL,
    `created_at`    DATETIME NOT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_activity_logs_actor_id` (`actor_id`),
    KEY `idx_activity_logs_action` (`action`),
    KEY `idx_activity_logs_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Table: notifications
-- Generic in-app notifications. `recipient_id` is a plain nullable
-- integer — NOT a foreign key — for the same reason as above.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `notifications` (
    `id`             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    `recipient_id`   INT UNSIGNED NULL DEFAULT NULL COMMENT 'Link to users.id once auth exists',
    `title`          VARCHAR(150) NOT NULL,
    `message`        TEXT NULL DEFAULT NULL,
    `type`           VARCHAR(30) NOT NULL DEFAULT 'info' COMMENT 'info, success, warning, error',
    `is_read`        TINYINT(1) NOT NULL DEFAULT 0,
    `read_at`        DATETIME NULL DEFAULT NULL,
    `created_at`     DATETIME NOT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_notifications_recipient_id` (`recipient_id`),
    KEY `idx_notifications_is_read` (`is_read`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET FOREIGN_KEY_CHECKS = 1;

-- ---------------------------------------------------------------------
-- Optional seed data
-- ---------------------------------------------------------------------
INSERT INTO `settings` (`setting_key`, `setting_value`, `updated_at`)
VALUES
    ('site_name', 'Admin Panel', NOW()),
    ('maintenance_mode', '0', NOW())
ON DUPLICATE KEY UPDATE `setting_key` = `setting_key`;
