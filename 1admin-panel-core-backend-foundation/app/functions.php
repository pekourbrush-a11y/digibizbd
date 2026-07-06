<?php
/**
 * =====================================================================
 * functions.php
 * ---------------------------------------------------------------------
 * Reusable, database-aware helper functions for core, non-authentication
 * infrastructure: application settings and activity/audit logging.
 *
 * SCOPE: No user accounts, login, sessions, password reset, or 2FA
 * logic lives here — that belongs to a future Authentication module.
 * These functions only depend on the tables created in database.sql
 * (settings, activity_logs, notifications).
 *
 * NOTE: These are plain helper functions, not controllers or routes.
 * =====================================================================
 */

if (!defined('APP_BOOTSTRAPPED')) {
    http_response_code(403);
    exit('Direct access forbidden.');
}

/* --------------------------------------------------------------------
 * SETTINGS (global key/value application settings)
 * ------------------------------------------------------------------ */

function get_setting(string $key, mixed $default = null): mixed
{
    $row = db()->fetchOne('SELECT setting_value FROM settings WHERE setting_key = ? LIMIT 1', [$key]);
    return $row['setting_value'] ?? $default;
}

function set_setting(string $key, string $value): void
{
    $sql = 'INSERT INTO settings (setting_key, setting_value, updated_at)
            VALUES (:k, :v, :u)
            ON DUPLICATE KEY UPDATE setting_value = :v2, updated_at = :u2';

    db()->execute($sql, [
        'k' => $key, 'v' => $value, 'u' => now_datetime(),
        'v2' => $value, 'u2' => now_datetime(),
    ]);
}

function get_all_settings(): array
{
    $rows = db()->fetchAll('SELECT setting_key, setting_value FROM settings');
    $result = [];
    foreach ($rows as $row) {
        $result[$row['setting_key']] = $row['setting_value'];
    }
    return $result;
}

/* --------------------------------------------------------------------
 * ACTIVITY LOGS (general "what happened" audit trail)
 * `actor_id` is a plain nullable integer — it is NOT a foreign key to
 * a users table, since no authentication/user table exists yet in
 * this foundation. Wire it up once your Authentication module exists.
 * ------------------------------------------------------------------ */

function log_activity(?int $actorId, string $action, string $description = '', ?string $subjectType = null, ?int $subjectId = null): void
{
    $sql = 'INSERT INTO activity_logs (actor_id, action, description, subject_type, subject_id, ip_address, user_agent, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)';

    db()->execute($sql, [
        $actorId, $action, $description, $subjectType, $subjectId, get_client_ip(), get_user_agent(), now_datetime(),
    ]);
}

function get_recent_activity(int $limit = 50): array
{
    $limit = max(1, min($limit, 200));
    return db()->fetchAll("SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT $limit");
}

/* --------------------------------------------------------------------
 * NOTIFICATIONS (generic in-app notifications)
 * `recipient_id` is a plain nullable integer for the same reason as
 * `actor_id` above — no FK to a users table in this foundation yet.
 * ------------------------------------------------------------------ */

function create_notification(?int $recipientId, string $title, string $message, string $type = 'info'): string
{
    $sql = 'INSERT INTO notifications (recipient_id, title, message, type, is_read, created_at)
            VALUES (?, ?, ?, ?, 0, ?)';
    return db()->insert($sql, [$recipientId, $title, $message, $type, now_datetime()]);
}

function get_unread_notifications(?int $recipientId, int $limit = 20): array
{
    $limit = max(1, min($limit, 100));

    if ($recipientId === null) {
        return db()->fetchAll(
            "SELECT * FROM notifications WHERE recipient_id IS NULL AND is_read = 0 ORDER BY created_at DESC LIMIT $limit"
        );
    }

    return db()->fetchAll(
        "SELECT * FROM notifications WHERE recipient_id = ? AND is_read = 0 ORDER BY created_at DESC LIMIT $limit",
        [$recipientId]
    );
}

function mark_notification_read(int $notificationId): int
{
    return db()->execute(
        'UPDATE notifications SET is_read = 1, read_at = ? WHERE id = ?',
        [now_datetime(), $notificationId]
    );
}
