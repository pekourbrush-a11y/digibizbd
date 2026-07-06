<?php
declare(strict_types=1);

/**
 * RememberMe
 * Secure "remember me" persistent login using the selector/validator
 * pattern (resistant to timing attacks and DB-dump token theft, since
 * only a hash of the validator is stored).
 *
 * Required table (MySQL):
 *
 * CREATE TABLE remember_tokens (
 *   id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *   user_id INT UNSIGNED NOT NULL,
 *   selector VARCHAR(24) NOT NULL UNIQUE,
 *   validator_hash CHAR(64) NOT NULL,
 *   expires_at DATETIME NOT NULL,
 *   created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *   INDEX (user_id)
 * ) ENGINE=InnoDB;
 */
final class RememberMe
{
    private const COOKIE_NAME = 'remember_me';
    private const TOKEN_TTL_DAYS = 30;

    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /** Issue a new remember-me token for a user and set the cookie. */
    public function createToken(int $userId): void
    {
        $selector = bin2hex(random_bytes(9));
        $validator = bin2hex(random_bytes(33));
        $validatorHash = hash('sha256', $validator);
        $expiresAt = (new DateTimeImmutable('+' . self::TOKEN_TTL_DAYS . ' days'))->format('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare(
            'INSERT INTO remember_tokens (user_id, selector, validator_hash, expires_at)
             VALUES (:user_id, :selector, :validator_hash, :expires_at)'
        );
        $stmt->execute([
            'user_id'        => $userId,
            'selector'       => $selector,
            'validator_hash' => $validatorHash,
            'expires_at'     => $expiresAt,
        ]);

        $this->setCookie($selector . ':' . $validator, self::TOKEN_TTL_DAYS * 86400);
    }

    /**
     * Validate the remember-me cookie. Returns the user_id on success,
     * or null if absent/invalid/expired. Rotates the token on success
     * (prevents replay if a stale cookie value leaks).
     */
    public function validate(): ?int
    {
        $cookie = $_COOKIE[self::COOKIE_NAME] ?? null;
        if (!$cookie || !str_contains($cookie, ':')) {
            return null;
        }

        [$selector, $validator] = explode(':', $cookie, 2);

        $stmt = $this->pdo->prepare('SELECT * FROM remember_tokens WHERE selector = :selector LIMIT 1');
        $stmt->execute(['selector' => $selector]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            return null;
        }

        if (new DateTimeImmutable($row['expires_at']) < new DateTimeImmutable()) {
            $this->deleteBySelector($selector);
            $this->clearCookie();
            return null;
        }

        $expectedHash = hash('sha256', $validator);
        if (!hash_equals($row['validator_hash'], $expectedHash)) {
            // Possible token theft/replay: invalidate all tokens for this user.
            $this->forgetAllForUser((int) $row['user_id']);
            $this->clearCookie();
            return null;
        }

        $userId = (int) $row['user_id'];

        // Rotate: delete old token, issue a new one bound to the same user.
        $this->deleteBySelector($selector);
        $this->createToken($userId);

        return $userId;
    }

    /** Forget the current device's remember-me token (e.g. on logout). */
    public function forget(): void
    {
        $cookie = $_COOKIE[self::COOKIE_NAME] ?? null;
        if ($cookie && str_contains($cookie, ':')) {
            [$selector] = explode(':', $cookie, 2);
            $this->deleteBySelector($selector);
        }
        $this->clearCookie();
    }

    /** Forget all remember-me tokens for a user (e.g. on password change, "log out everywhere"). */
    public function forgetAllForUser(int $userId): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM remember_tokens WHERE user_id = :user_id');
        $stmt->execute(['user_id' => $userId]);
    }

    private function deleteBySelector(string $selector): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM remember_tokens WHERE selector = :selector');
        $stmt->execute(['selector' => $selector]);
    }

    private function setCookie(string $value, int $lifetimeSeconds): void
    {
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        setcookie(self::COOKIE_NAME, $value, [
            'expires'  => time() + $lifetimeSeconds,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $isHttps,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        $_COOKIE[self::COOKIE_NAME] = $value;
    }

    private function clearCookie(): void
    {
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
        setcookie(self::COOKIE_NAME, '', [
            'expires'  => time() - 3600,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $isHttps,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        unset($_COOKIE[self::COOKIE_NAME]);
    }
}
