<?php
declare(strict_types=1);

require_once __DIR__ . '/session.php';
require_once __DIR__ . '/password.php';
require_once __DIR__ . '/two_factor.php';
require_once __DIR__ . '/rate_limiter.php';
require_once __DIR__ . '/remember_me.php';
require_once __DIR__ . '/sanitizer.php';
require_once __DIR__ . '/validator.php';

/**
 * Auth
 * Central authentication service: registration, login (with optional
 * TOTP 2FA and remember-me), logout, and session-based user resolution.
 *
 * Required table (MySQL) — extend as needed:
 *
 * CREATE TABLE users (
 *   id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *   name VARCHAR(191) NOT NULL,
 *   email VARCHAR(191) NOT NULL UNIQUE,
 *   password_hash VARCHAR(255) NOT NULL,
 *   two_factor_secret VARCHAR(64) NULL,
 *   two_factor_enabled TINYINT(1) NOT NULL DEFAULT 0,
 *   two_factor_backup_codes TEXT NULL,
 *   is_active TINYINT(1) NOT NULL DEFAULT 1,
 *   created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *   updated_at DATETIME NULL
 * ) ENGINE=InnoDB;
 */
final class Auth
{
    private const SESSION_USER_KEY = 'auth_user_id';
    private const SESSION_PENDING_2FA_KEY = 'auth_pending_2fa_user_id';
    private const MAX_LOGIN_ATTEMPTS = 5;
    private const LOGIN_DECAY_MINUTES = 15;

    private PDO $pdo;
    private RateLimiter $rateLimiter;
    private RememberMe $rememberMe;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
        $this->rateLimiter = new RateLimiter($pdo);
        $this->rememberMe = new RememberMe($pdo);
        SessionManager::start();
    }

    /**
     * Register a new user. Returns ['success' => bool, 'errors' => [...], 'user_id' => ?int]
     */
    public function register(string $name, string $email, string $plainPassword): array
    {
        $name = Sanitizer::cleanString($name);
        $email = Sanitizer::cleanEmail($email);

        $errors = [];
        if ($name === '') {
            $errors[] = 'Name is required.';
        }
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'A valid email is required.';
        }
        $errors = array_merge($errors, Password::validateStrength($plainPassword, ['email' => $email, 'name' => $name]));

        if (!empty($errors)) {
            return ['success' => false, 'errors' => $errors, 'user_id' => null];
        }

        $existing = $this->findUserByEmail($email);
        if ($existing !== null) {
            return ['success' => false, 'errors' => ['An account with this email already exists.'], 'user_id' => null];
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO users (name, email, password_hash, created_at) VALUES (:name, :email, :hash, NOW())'
        );
        $stmt->execute([
            'name'  => $name,
            'email' => $email,
            'hash'  => Password::hash($plainPassword),
        ]);

        return ['success' => true, 'errors' => [], 'user_id' => (int) $this->pdo->lastInsertId()];
    }

    /**
     * Attempt to log a user in.
     *
     * Returns one of:
     *   ['status' => 'success', 'user' => [...]]
     *   ['status' => 'requires_2fa']
     *   ['status' => 'locked', 'retry_after' => int]
     *   ['status' => 'failed', 'errors' => [...]]
     */
    public function attemptLogin(string $email, string $plainPassword, bool $remember = false, ?string $clientIp = null): array
    {
        $email = Sanitizer::cleanEmail($email);
        $clientIp = $clientIp ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown');

        $ipKey = RateLimiter::makeKey('login_ip', $clientIp);
        $emailKey = RateLimiter::makeKey('login_email', $email);

        if ($this->rateLimiter->tooManyAttempts($ipKey, self::MAX_LOGIN_ATTEMPTS, self::LOGIN_DECAY_MINUTES)
            || $this->rateLimiter->tooManyAttempts($emailKey, self::MAX_LOGIN_ATTEMPTS, self::LOGIN_DECAY_MINUTES)
        ) {
            $retryAfter = max($this->rateLimiter->availableIn($ipKey), $this->rateLimiter->availableIn($emailKey));
            return ['status' => 'locked', 'retry_after' => $retryAfter];
        }

        $user = $this->findUserByEmail($email);

        if ($user === null || !Password::verify($plainPassword, $user['password_hash'])) {
            $this->rateLimiter->hit($ipKey, self::MAX_LOGIN_ATTEMPTS, self::LOGIN_DECAY_MINUTES);
            $this->rateLimiter->hit($emailKey, self::MAX_LOGIN_ATTEMPTS, self::LOGIN_DECAY_MINUTES);
            return ['status' => 'failed', 'errors' => ['Invalid email or password.']];
        }

        if ((int) ($user['is_active'] ?? 1) === 0) {
            return ['status' => 'failed', 'errors' => ['This account has been disabled.']];
        }

        // Successful password check clears throttling counters.
        $this->rateLimiter->clear($ipKey);
        $this->rateLimiter->clear($emailKey);

        if (Password::needsRehash($user['password_hash'])) {
            $this->updatePasswordHash((int) $user['id'], Password::hash($plainPassword));
        }

        if (!empty($user['two_factor_enabled'])) {
            SessionManager::regenerate();
            SessionManager::set(self::SESSION_PENDING_2FA_KEY, (int) $user['id']);
            SessionManager::set('auth_remember_pending', $remember);
            return ['status' => 'requires_2fa'];
        }

        $this->completeLogin((int) $user['id'], $remember);
        return ['status' => 'success', 'user' => $this->sanitizeUser($user)];
    }

    /**
     * Complete login after a successful TOTP check (second factor).
     */
    public function completeTwoFactorLogin(string $totpCode, ?string $backupCode = null): array
    {
        $userId = SessionManager::get(self::SESSION_PENDING_2FA_KEY);
        if (!$userId) {
            return ['status' => 'failed', 'errors' => ['No pending two-factor login.']];
        }

        $key = RateLimiter::makeKey('2fa', (string) $userId);
        if ($this->rateLimiter->tooManyAttempts($key, 5, 15)) {
            return ['status' => 'locked', 'retry_after' => $this->rateLimiter->availableIn($key)];
        }

        $user = $this->findUserById((int) $userId);
        if ($user === null) {
            return ['status' => 'failed', 'errors' => ['Invalid session.']];
        }

        $verified = false;
        if ($totpCode !== '' && !empty($user['two_factor_secret'])) {
            $verified = TwoFactorAuth::verifyCode($user['two_factor_secret'], $totpCode);
        }

        if (!$verified && $backupCode) {
            $verified = $this->consumeBackupCode((int) $user['id'], $backupCode);
        }

        if (!$verified) {
            $this->rateLimiter->hit($key, 5, 15);
            return ['status' => 'failed', 'errors' => ['Invalid authentication code.']];
        }

        $this->rateLimiter->clear($key);
        $remember = (bool) SessionManager::get('auth_remember_pending', false);
        SessionManager::remove(self::SESSION_PENDING_2FA_KEY);
        SessionManager::remove('auth_remember_pending');

        $this->completeLogin((int) $user['id'], $remember);
        return ['status' => 'success', 'user' => $this->sanitizeUser($user)];
    }

    private function completeLogin(int $userId, bool $remember): void
    {
        SessionManager::regenerate();
        SessionManager::set(self::SESSION_USER_KEY, $userId);
        SessionManager::set('auth_login_at', time());

        if ($remember) {
            $this->rememberMe->createToken($userId);
        }
    }

    /** Attempt silent login via remember-me cookie (call on bootstrap if session is anonymous). */
    public function attemptRememberMeLogin(): bool
    {
        if ($this->isAuthenticated()) {
            return true;
        }
        $userId = $this->rememberMe->validate();
        if ($userId === null) {
            return false;
        }
        $user = $this->findUserById($userId);
        if ($user === null || (int) ($user['is_active'] ?? 1) === 0) {
            return false;
        }
        SessionManager::regenerate();
        SessionManager::set(self::SESSION_USER_KEY, $userId);
        return true;
    }

    public function isAuthenticated(): bool
    {
        return SessionManager::has(self::SESSION_USER_KEY);
    }

    public function id(): ?int
    {
        $id = SessionManager::get(self::SESSION_USER_KEY);
        return $id !== null ? (int) $id : null;
    }

    public function user(): ?array
    {
        $id = $this->id();
        if ($id === null) {
            return null;
        }
        $user = $this->findUserById($id);
        return $user ? $this->sanitizeUser($user) : null;
    }

    /** Redirect-and-exit guard for pages requiring authentication. */
    public function requireLogin(string $redirectTo = '/login.php'): void
    {
        if (!$this->isAuthenticated() && !$this->attemptRememberMeLogin()) {
            header('Location: ' . $redirectTo);
            exit;
        }
    }

    public function logout(): void
    {
        $this->rememberMe->forget();
        SessionManager::destroy();
    }

    // ---- Two-factor management ---------------------------------------------

    public function enableTwoFactor(int $userId, string $secret): array
    {
        $backupCodes = TwoFactorAuth::generateBackupCodes();
        $hashedCodes = array_map([TwoFactorAuth::class, 'hashBackupCode'], $backupCodes);

        $stmt = $this->pdo->prepare(
            'UPDATE users SET two_factor_secret = :secret, two_factor_enabled = 1,
             two_factor_backup_codes = :codes, updated_at = NOW() WHERE id = :id'
        );
        $stmt->execute([
            'secret' => $secret,
            'codes'  => json_encode($hashedCodes),
            'id'     => $userId,
        ]);

        return $backupCodes; // show once to the user
    }

    public function disableTwoFactor(int $userId): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE users SET two_factor_secret = NULL, two_factor_enabled = 0,
             two_factor_backup_codes = NULL, updated_at = NOW() WHERE id = :id'
        );
        $stmt->execute(['id' => $userId]);
    }

    private function consumeBackupCode(int $userId, string $code): bool
    {
        $user = $this->findUserById($userId);
        if (!$user || empty($user['two_factor_backup_codes'])) {
            return false;
        }
        $hashed = json_decode($user['two_factor_backup_codes'], true) ?: [];
        $codeHash = TwoFactorAuth::hashBackupCode($code);

        $index = array_search($codeHash, $hashed, true);
        if ($index === false) {
            return false;
        }

        unset($hashed[$index]);
        $stmt = $this->pdo->prepare('UPDATE users SET two_factor_backup_codes = :codes WHERE id = :id');
        $stmt->execute(['codes' => json_encode(array_values($hashed)), 'id' => $userId]);
        return true;
    }

    // ---- Password management ------------------------------------------------

    public function updatePasswordHash(int $userId, string $newHash): void
    {
        $stmt = $this->pdo->prepare('UPDATE users SET password_hash = :hash, updated_at = NOW() WHERE id = :id');
        $stmt->execute(['hash' => $newHash, 'id' => $userId]);
    }

    public function changePassword(int $userId, string $currentPassword, string $newPassword): array
    {
        $user = $this->findUserById($userId);
        if (!$user || !Password::verify($currentPassword, $user['password_hash'])) {
            return ['success' => false, 'errors' => ['Current password is incorrect.']];
        }

        $errors = Password::validateStrength($newPassword, ['email' => $user['email']]);
        if (!empty($errors)) {
            return ['success' => false, 'errors' => $errors];
        }

        $this->updatePasswordHash($userId, Password::hash($newPassword));
        $this->rememberMe->forgetAllForUser($userId); // force re-auth on other devices
        return ['success' => true, 'errors' => []];
    }

    // ---- Lookups --------------------------------------------------------------

    public function findUserByEmail(string $email): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => strtolower($email)]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    public function findUserById(int $id): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM users WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /** Strip sensitive fields before returning a user array to callers/views. */
    private function sanitizeUser(array $user): array
    {
        unset($user['password_hash'], $user['two_factor_secret'], $user['two_factor_backup_codes']);
        return $user;
    }
}
