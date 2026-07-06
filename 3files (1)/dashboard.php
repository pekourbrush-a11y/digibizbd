<?php
declare(strict_types=1);

/**
 * api/dashboard.php
 *
 * Read-only aggregate view for the authenticated user's dashboard:
 * profile summary, security status, recent logins, unread notification
 * count, and active session count. Combines data already modeled by
 * users / login_history / notifications / remember_tokens.
 *
 *   GET /api/dashboard.php -> { success, dashboard }
 */

require_once __DIR__ . '/auth.php';

require_method('GET');
$user = require_auth();
$pdo = get_pdo();
$userId = (int) $user['id'];

$fullUser = current_auth()->findUserById($userId);

$summary = [
    'id'                 => $userId,
    'name'               => $user['name'],
    'email'              => $user['email'],
    'member_since'       => $user['created_at'] ?? null,
    'two_factor_enabled' => (bool) ($fullUser['two_factor_enabled'] ?? false),
];

// Recent login history (table defined in api/login-history.php).
$recentLogins = [];
try {
    $stmt = $pdo->prepare(
        'SELECT ip_address, user_agent, status, created_at FROM login_history
         WHERE user_id = :id ORDER BY created_at DESC LIMIT 5'
    );
    $stmt->execute(['id' => $userId]);
    $recentLogins = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    // Table may not exist yet in a fresh install; degrade gracefully.
    $recentLogins = [];
}

// Unread notification count (table defined in api/notifications.php).
$unreadNotifications = 0;
try {
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM notifications WHERE user_id = :id AND read_at IS NULL');
    $stmt->execute(['id' => $userId]);
    $unreadNotifications = (int) $stmt->fetchColumn();
} catch (PDOException $e) {
    $unreadNotifications = 0;
}

// Active "remember me" device count (table defined in root remember_me.php).
$activeSessions = 0;
try {
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM remember_tokens WHERE user_id = :id AND expires_at > NOW()');
    $stmt->execute(['id' => $userId]);
    $activeSessions = (int) $stmt->fetchColumn();
} catch (PDOException $e) {
    $activeSessions = 0;
}

json_ok([
    'dashboard' => [
        'profile'              => $summary,
        'recent_logins'        => $recentLogins,
        'unread_notifications' => $unreadNotifications,
        'active_sessions'      => $activeSessions,
    ],
]);
