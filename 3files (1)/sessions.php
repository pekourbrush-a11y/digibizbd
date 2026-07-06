<?php
declare(strict_types=1);

/**
 * api/sessions.php
 *
 * Manage the authenticated user's "remember me" devices (from
 * remember_me.php / the remember_tokens table). The current browser
 * session itself is separate (server-side PHP session) and always
 * implicitly "active" while the request is authenticated.
 *
 *   GET    /api/sessions.php                    -> list active devices
 *   DELETE /api/sessions.php?selector=abc123     -> revoke one device
 *   POST   /api/sessions.php?action=revoke-all   -> revoke all devices
 */

require_once __DIR__ . '/auth.php';

$user = require_auth();
$pdo = get_pdo();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = Sanitizer::cleanString($_GET['action'] ?? $_POST['action'] ?? '');

/** Extract the selector portion of the current remember-me cookie, if any. */
function current_device_selector(): ?string
{
    $cookie = $_COOKIE['remember_me'] ?? null;
    if (!$cookie || !str_contains($cookie, ':')) {
        return null;
    }
    [$selector] = explode(':', $cookie, 2);
    return $selector;
}

if ($method === 'GET') {
    $stmt = $pdo->prepare(
        'SELECT selector, created_at, expires_at FROM remember_tokens
         WHERE user_id = :uid AND expires_at > NOW() ORDER BY created_at DESC'
    );
    $stmt->execute(['uid' => $user['id']]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $currentSelector = current_device_selector();
    $devices = array_map(static function (array $row) use ($currentSelector): array {
        return [
            'device_id'  => $row['selector'],
            'created_at' => $row['created_at'],
            'expires_at' => $row['expires_at'],
            'is_current' => $currentSelector !== null && hash_equals($row['selector'], $currentSelector),
        ];
    }, $rows);

    json_ok(['sessions' => $devices]);
}

if ($method === 'DELETE') {
    require_csrf();
    $selector = Sanitizer::cleanString($_GET['selector'] ?? '');
    if ($selector === '') {
        json_error('A device selector is required.', 422);
    }

    $stmt = $pdo->prepare('DELETE FROM remember_tokens WHERE selector = :selector AND user_id = :uid');
    $stmt->execute(['selector' => $selector, 'uid' => $user['id']]);

    if ($stmt->rowCount() === 0) {
        json_error('Device not found.', 404);
    }
    json_ok(['message' => 'Device signed out.']);
}

if ($method === 'POST' && $action === 'revoke-all') {
    require_csrf();
    $rememberMe = new RememberMe($pdo);
    $rememberMe->forgetAllForUser((int) $user['id']);
    json_ok(['message' => 'All devices have been signed out.']);
}

json_error('Unknown action or method.', 404);
