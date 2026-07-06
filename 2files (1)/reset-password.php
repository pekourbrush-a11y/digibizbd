<?php
declare(strict_types=1);

/**
 * reset-password.php
 * Validates a reset token (selector = uid, secret = token, compared
 * via hash) and, on a valid POST, updates the user's password. Tokens
 * are single-use and time-limited (see forgot-password.php).
 */

require_once __DIR__ . '/session.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/sanitizer.php';
require_once __DIR__ . '/validator.php';
require_once __DIR__ . '/password.php';
require_once __DIR__ . '/rate_limiter.php';
require_once __DIR__ . '/auth.php';

SessionManager::start();
Security::setSecurityHeaders();

function get_pdo(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $host = getenv('DB_HOST') ?: '127.0.0.1';
        $name = getenv('DB_NAME') ?: 'app';
        $user = getenv('DB_USER') ?: 'app';
        $pass = getenv('DB_PASS') ?: '';
        $dsn = "mysql:host={$host};dbname={$name};charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }
    return $pdo;
}

/** Look up a valid, unused, unexpired reset record for a given user id + raw token. */
function find_valid_reset(PDO $pdo, int $userId, string $rawToken): ?array
{
    $stmt = $pdo->prepare(
        'SELECT * FROM password_resets WHERE user_id = :uid AND used_at IS NULL AND expires_at > NOW()
         ORDER BY created_at DESC LIMIT 1'
    );
    $stmt->execute(['uid' => $userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return null;
    }
    if (!hash_equals($row['token_hash'], hash('sha256', $rawToken))) {
        return null;
    }
    return $row;
}

$pdo = get_pdo();
$rateLimiter = new RateLimiter($pdo);
$auth = new Auth($pdo);

$userId = Sanitizer::cleanInt($_GET['uid'] ?? $_POST['uid'] ?? 0);
$token = Sanitizer::cleanString($_GET['token'] ?? $_POST['token'] ?? '');

$errors = [];
$success = false;
$tokenValid = $userId > 0 && $token !== '';

if ($tokenValid) {
    $ipKey = RateLimiter::makeKey('reset_pw_ip', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
    if ($rateLimiter->tooManyAttempts($ipKey, 10, 15)) {
        $tokenValid = false;
        $errors[] = 'Too many attempts. Please try again later.';
    } else {
        $reset = find_valid_reset($pdo, $userId, $token);
        $tokenValid = $reset !== null;
        if (!$tokenValid) {
            $rateLimiter->hit($ipKey, 10, 15);
            $errors[] = 'This password reset link is invalid or has expired.';
        }
    }
}

if ($tokenValid && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['password'])) {
    if (!CSRF::verifyRequest('reset_password')) {
        $errors[] = 'Your session expired. Please try again.';
    } else {
        $validator = new Validator($_POST, [
            'password'              => 'required|password_strength',
            'password_confirmation' => 'required|matches:password',
        ]);

        if ($validator->fails()) {
            $errors = array_merge(...array_values($validator->errors()));
        } else {
            $user = $auth->findUserById($userId);
            if ($user === null) {
                $errors[] = 'Account not found.';
            } else {
                $newPassword = (string) $_POST['password'];
                $strengthErrors = Password::validateStrength($newPassword, ['email' => $user['email']]);

                if (!empty($strengthErrors)) {
                    $errors = $strengthErrors;
                } else {
                    $auth->updatePasswordHash($userId, Password::hash($newPassword));

                    // Mark token used and invalidate any other outstanding tokens for this user.
                    $stmt = $pdo->prepare('UPDATE password_resets SET used_at = NOW() WHERE user_id = :uid AND used_at IS NULL');
                    $stmt->execute(['uid' => $userId]);

                    $success = true;
                }
            }
        }
    }
}

$csrfToken = CSRF::getToken('reset_password');
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Reset password</title></head>
<body>
<?php foreach ($errors as $error): ?>
    <p style="color:red;"><?= Security::escape($error) ?></p>
<?php endforeach; ?>

<?php if ($success): ?>
    <p>Your password has been reset successfully. You can now <a href="/login.php">log in</a>.</p>
<?php elseif ($tokenValid): ?>
    <form method="post" action="/reset-password.php">
        <input type="hidden" name="csrf_token" value="<?= Security::escape($csrfToken) ?>">
        <input type="hidden" name="uid" value="<?= (int) $userId ?>">
        <input type="hidden" name="token" value="<?= Security::escape($token) ?>">
        <label>New password: <input type="password" name="password" required autocomplete="new-password"></label>
        <label>Confirm password: <input type="password" name="password_confirmation" required autocomplete="new-password"></label>
        <button type="submit">Reset password</button>
    </form>
<?php else: ?>
    <p><a href="/forgot-password.php">Request a new password reset link</a>.</p>
<?php endif; ?>
</body>
</html>
