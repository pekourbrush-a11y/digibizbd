<?php
declare(strict_types=1);

/**
 * api/security.php
 *
 * Security overview and account-protection actions.
 *
 *   GET  /api/security.php                          -> { success, security }
 *   POST /api/security.php?action=change-password    { current_password, new_password, new_password_confirmation }
 *   POST /api/security.php?action=revoke-all-sessions -> forgets all remember-me devices except a fresh one for this session
 */

require_once __DIR__ . '/auth.php';

$user = require_auth();
$pdo = get_pdo();
$auth = current_auth();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = Sanitizer::cleanString($_GET['action'] ?? $_POST['action'] ?? '');

if ($method === 'GET' && $action === '') {
    $fullUser = $auth->findUserById((int) $user['id']);

    $stmt = $pdo->prepare('SELECT COUNT(*) FROM remember_tokens WHERE user_id = :id AND expires_at > NOW()');
    $stmt->execute(['id' => $user['id']]);
    $activeDevices = (int) $stmt->fetchColumn();

    $recentFailedLogins = 0;
    try {
        $stmt = $pdo->prepare(
            "SELECT COUNT(*) FROM login_history WHERE user_id = :id AND status = 'failed'
             AND created_at > (NOW() - INTERVAL 7 DAY)"
        );
        $stmt->execute(['id' => $user['id']]);
        $recentFailedLogins = (int) $stmt->fetchColumn();
    } catch (PDOException $e) {
        $recentFailedLogins = 0;
    }

    json_ok([
        'security' => [
            'two_factor_enabled'    => (bool) ($fullUser['two_factor_enabled'] ?? false),
            'password_last_updated' => $fullUser['updated_at'] ?? null,
            'active_devices'        => $activeDevices,
            'recent_failed_logins'  => $recentFailedLogins,
        ],
    ]);
}

if ($method === 'POST' && $action === 'change-password') {
    require_csrf();
    $input = json_input();

    $validator = new Validator($input, [
        'current_password'          => 'required',
        'new_password'              => 'required|password_strength',
        'new_password_confirmation' => 'required|matches:new_password',
    ]);
    if ($validator->fails()) {
        json_error('Validation failed.', 422, ['errors' => $validator->errors()]);
    }

    $result = $auth->changePassword(
        (int) $user['id'],
        (string) $input['current_password'],
        (string) $input['new_password']
    );

    if (!$result['success']) {
        json_error($result['errors'][0] ?? 'Unable to change password.', 422, ['errors' => $result['errors']]);
    }

    json_ok(['message' => 'Password updated. You have been logged out of other devices.']);
}

if ($method === 'POST' && $action === 'revoke-all-sessions') {
    require_csrf();
    $rememberMe = new RememberMe($pdo);
    $rememberMe->forgetAllForUser((int) $user['id']);
    json_ok(['message' => 'All remembered devices have been signed out.']);
}

json_error('Unknown action or method.', 404);
