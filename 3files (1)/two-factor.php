<?php
declare(strict_types=1);

/**
 * api/two-factor.php
 *
 * Google-Authenticator-compatible TOTP setup and management.
 *
 *   GET  /api/two-factor.php                          -> { success, enabled }
 *   POST /api/two-factor.php?action=setup              -> { secret, otpauth_url, qr_code_url }
 *   POST /api/two-factor.php?action=confirm  { totp_code } -> enables 2FA, returns backup_codes (shown once)
 *   POST /api/two-factor.php?action=disable  { password }
 *   POST /api/two-factor.php?action=regenerate-backup-codes { password } -> new backup_codes (shown once)
 */

require_once __DIR__ . '/auth.php';

const PENDING_2FA_SECRET_SESSION_KEY = 'pending_2fa_secret';

$user = require_auth();
$pdo = get_pdo();
$auth = current_auth();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = Sanitizer::cleanString($_GET['action'] ?? $_POST['action'] ?? '');

$fullUser = $auth->findUserById((int) $user['id']);
if ($fullUser === null) {
    json_error('User not found.', 404);
}

if ($method === 'GET' && $action === '') {
    json_ok(['enabled' => (bool) $fullUser['two_factor_enabled']]);
}

if ($method === 'POST' && $action === 'setup') {
    require_csrf();

    if ((bool) $fullUser['two_factor_enabled']) {
        json_error('Two-factor authentication is already enabled.', 422);
    }

    $secret = TwoFactorAuth::generateSecret();
    SessionManager::set(PENDING_2FA_SECRET_SESSION_KEY, $secret);

    $issuer = $_SERVER['HTTP_HOST'] ?? 'App';
    json_ok([
        'secret'      => $secret,
        'otpauth_url' => TwoFactorAuth::getQRCodeUrl($issuer, $fullUser['email'], $secret),
        'qr_code_url' => TwoFactorAuth::getQRCodeImageUrl($issuer, $fullUser['email'], $secret),
    ]);
}

if ($method === 'POST' && $action === 'confirm') {
    require_csrf();
    $input = json_input();
    $code = Sanitizer::digitsOnly((string) ($input['totp_code'] ?? ''));

    $pendingSecret = SessionManager::get(PENDING_2FA_SECRET_SESSION_KEY);
    if (!$pendingSecret) {
        json_error('No pending two-factor setup. Please start again.', 422);
    }

    if ($code === '' || !TwoFactorAuth::verifyCode($pendingSecret, $code)) {
        json_error('Invalid authentication code.', 422);
    }

    $backupCodes = $auth->enableTwoFactor((int) $user['id'], $pendingSecret);
    SessionManager::remove(PENDING_2FA_SECRET_SESSION_KEY);

    json_ok([
        'message'      => 'Two-factor authentication enabled.',
        'backup_codes' => $backupCodes,
    ]);
}

if ($method === 'POST' && $action === 'disable') {
    require_csrf();
    $input = json_input();
    $password = (string) ($input['password'] ?? '');

    if (!Password::verify($password, $fullUser['password_hash'])) {
        json_error('Password confirmation is incorrect.', 403);
    }

    $auth->disableTwoFactor((int) $user['id']);
    json_ok(['message' => 'Two-factor authentication disabled.']);
}

if ($method === 'POST' && $action === 'regenerate-backup-codes') {
    require_csrf();
    $input = json_input();
    $password = (string) ($input['password'] ?? '');

    if (!Password::verify($password, $fullUser['password_hash'])) {
        json_error('Password confirmation is incorrect.', 403);
    }
    if (!(bool) $fullUser['two_factor_enabled']) {
        json_error('Two-factor authentication is not enabled.', 422);
    }

    $backupCodes = TwoFactorAuth::generateBackupCodes();
    $hashed = array_map([TwoFactorAuth::class, 'hashBackupCode'], $backupCodes);

    $stmt = $pdo->prepare('UPDATE users SET two_factor_backup_codes = :codes, updated_at = NOW() WHERE id = :id');
    $stmt->execute(['codes' => json_encode($hashed), 'id' => $user['id']]);

    json_ok(['backup_codes' => $backupCodes]);
}

json_error('Unknown action or method.', 404);
