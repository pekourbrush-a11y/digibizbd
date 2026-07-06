<?php
declare(strict_types=1);

/**
 * forgot-password.php
 * Accepts an email address, generates a single-use, time-limited
 * reset token (stored hashed), and emails a reset link. Always shows
 * a generic success message regardless of whether the email exists,
 * to avoid user-enumeration.
 *
 * Required table (MySQL):
 *
 * CREATE TABLE password_resets (
 *   id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *   user_id INT UNSIGNED NOT NULL,
 *   token_hash CHAR(64) NOT NULL UNIQUE,
 *   expires_at DATETIME NOT NULL,
 *   used_at DATETIME NULL,
 *   created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *   INDEX (user_id)
 * ) ENGINE=InnoDB;
 */

require_once __DIR__ . '/session.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/sanitizer.php';
require_once __DIR__ . '/validator.php';
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

const RESET_TOKEN_TTL_MINUTES = 60;

/** Send the reset email. Wire up your mailer (PHPMailer/Symfony Mailer/etc) here. */
function send_reset_email(string $toEmail, string $resetUrl): void
{
    $subject = 'Reset your password';
    $body = "We received a request to reset your password.\n\n"
        . "Reset link (valid for " . RESET_TOKEN_TTL_MINUTES . " minutes):\n{$resetUrl}\n\n"
        . "If you did not request this, you can safely ignore this email.";
    $headers = "From: no-reply@" . ($_SERVER['HTTP_HOST'] ?? 'example.com') . "\r\n"
        . "Content-Type: text/plain; charset=UTF-8";

    // mail() is a placeholder; swap in a proper transactional email service in production.
    @mail($toEmail, $subject, $body, $headers);
}

$pdo = get_pdo();
$rateLimiter = new RateLimiter($pdo);
$genericMessage = 'If an account exists for that email, a password reset link has been sent.';
$message = null;
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!CSRF::verifyRequest('forgot_password')) {
        $errors[] = 'Your session expired. Please try again.';
    } else {
        $validator = new Validator($_POST, ['email' => 'required|email']);
        if ($validator->fails()) {
            $errors[] = $validator->firstError() ?? 'Please provide a valid email.';
        } else {
            $email = Sanitizer::cleanEmail($_POST['email']);
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

            $ipKey = RateLimiter::makeKey('forgot_pw_ip', $ip);
            $emailKey = RateLimiter::makeKey('forgot_pw_email', $email);

            if ($rateLimiter->tooManyAttempts($ipKey, 5, 15) || $rateLimiter->tooManyAttempts($emailKey, 3, 30)) {
                // Still show the generic message; do not reveal throttling to a potential attacker.
                $message = $genericMessage;
            } else {
                $rateLimiter->hit($ipKey, 5, 15);
                $rateLimiter->hit($emailKey, 3, 30);

                $auth = new Auth($pdo);
                $user = $auth->findUserByEmail($email);

                if ($user !== null) {
                    $token = bin2hex(random_bytes(32));
                    $tokenHash = hash('sha256', $token);
                    $expiresAt = (new DateTimeImmutable('+' . RESET_TOKEN_TTL_MINUTES . ' minutes'))->format('Y-m-d H:i:s');

                    // Invalidate previous outstanding tokens for this user.
                    $stmt = $pdo->prepare('DELETE FROM password_resets WHERE user_id = :uid AND used_at IS NULL');
                    $stmt->execute(['uid' => $user['id']]);

                    $stmt = $pdo->prepare(
                        'INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (:uid, :hash, :exp)'
                    );
                    $stmt->execute(['uid' => $user['id'], 'hash' => $tokenHash, 'exp' => $expiresAt]);

                    $scheme = Security::isHttps() ? 'https' : 'http';
                    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
                    $resetUrl = "{$scheme}://{$host}/reset-password.php?token=" . urlencode($token) . '&uid=' . (int) $user['id'];

                    send_reset_email($user['email'], $resetUrl);
                }

                $message = $genericMessage;
            }
        }
    }
}

$csrfToken = CSRF::getToken('forgot_password');
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Forgot password</title></head>
<body>
<?php foreach ($errors as $error): ?>
    <p style="color:red;"><?= Security::escape($error) ?></p>
<?php endforeach; ?>
<?php if ($message): ?>
    <p><?= Security::escape($message) ?></p>
<?php else: ?>
    <form method="post" action="/forgot-password.php">
        <input type="hidden" name="csrf_token" value="<?= Security::escape($csrfToken) ?>">
        <label>Email: <input type="email" name="email" required></label>
        <button type="submit">Send reset link</button>
    </form>
<?php endif; ?>
</body>
</html>
