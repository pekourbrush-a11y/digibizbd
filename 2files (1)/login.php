<?php
declare(strict_types=1);

/**
 * login.php
 * Handles the login form submission (including optional TOTP 2FA step
 * and "remember me"). Include your own header/HTML around this, or
 * adapt the JSON branch for a JS-driven form. This file intentionally
 * contains no UI markup beyond a minimal fallback form.
 */

require_once __DIR__ . '/session.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/sanitizer.php';
require_once __DIR__ . '/validator.php';
require_once __DIR__ . '/auth.php';

SessionManager::start();
Security::setSecurityHeaders();

/**
 * ---- Database bootstrap -------------------------------------------------
 * Adjust via environment variables in your deployment (do not hardcode
 * production credentials). Falls back to local defaults for convenience.
 */
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

$auth = new Auth(get_pdo());
$errors = [];
$requiresTwoFactor = SessionManager::has('auth_pending_2fa_user_id');

// Already logged in? Try silent remember-me login, then redirect if authenticated.
if ($auth->isAuthenticated() || $auth->attemptRememberMeLogin()) {
    header('Location: /dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyRequest('login')) {
        $errors[] = 'Your session expired. Please try again.';
    } elseif (isset($_POST['totp_code']) || isset($_POST['backup_code'])) {
        // Step 2: second-factor verification.
        $totp = Sanitizer::digitsOnly((string) ($_POST['totp_code'] ?? ''));
        $backup = Sanitizer::cleanString((string) ($_POST['backup_code'] ?? ''));

        $result = $auth->completeTwoFactorLogin($totp, $backup !== '' ? $backup : null);

        if ($result['status'] === 'success') {
            header('Location: /dashboard.php');
            exit;
        }
        if ($result['status'] === 'locked') {
            $errors[] = 'Too many attempts. Try again in ' . (int) ceil($result['retry_after'] / 60) . ' minute(s).';
        } else {
            $errors = $result['errors'] ?? ['Invalid authentication code.'];
        }
        $requiresTwoFactor = true;
    } else {
        // Step 1: primary credentials.
        $validator = new Validator($_POST, [
            'email'    => 'required|email',
            'password' => 'required',
        ]);

        if ($validator->fails()) {
            $errors[] = $validator->firstError() ?? 'Invalid input.';
        } else {
            $email = Sanitizer::cleanEmail($_POST['email']);
            $password = (string) $_POST['password']; // do not sanitize/strip password content
            $remember = Sanitizer::cleanBool($_POST['remember'] ?? false);

            $result = $auth->attemptLogin($email, $password, $remember);

            switch ($result['status']) {
                case 'success':
                    header('Location: /dashboard.php');
                    exit;
                case 'requires_2fa':
                    $requiresTwoFactor = true;
                    break;
                case 'locked':
                    $errors[] = 'Too many failed attempts. Try again in ' . (int) ceil($result['retry_after'] / 60) . ' minute(s).';
                    break;
                default:
                    $errors = $result['errors'] ?? ['Invalid email or password.'];
            }
        }
    }
}

$csrfToken = CSRF::getToken('login');
?>
<!-- Minimal fallback form. Replace with your own template/UI as needed. -->
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Login</title></head>
<body>
<?php foreach ($errors as $error): ?>
    <p style="color:red;"><?= Security::escape($error) ?></p>
<?php endforeach; ?>

<?php if ($requiresTwoFactor): ?>
    <form method="post" action="/login.php">
        <input type="hidden" name="csrf_token" value="<?= Security::escape($csrfToken) ?>">
        <label>Authentication code: <input type="text" name="totp_code" inputmode="numeric" maxlength="6" autocomplete="one-time-code"></label>
        <label>Or backup code: <input type="text" name="backup_code"></label>
        <button type="submit">Verify</button>
    </form>
<?php else: ?>
    <form method="post" action="/login.php">
        <input type="hidden" name="csrf_token" value="<?= Security::escape($csrfToken) ?>">
        <label>Email: <input type="email" name="email" required autocomplete="username"></label>
        <label>Password: <input type="password" name="password" required autocomplete="current-password"></label>
        <label><input type="checkbox" name="remember" value="1"> Remember me</label>
        <button type="submit">Log in</button>
    </form>
<?php endif; ?>
</body>
</html>
