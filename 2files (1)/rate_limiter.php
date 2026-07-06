<?php
declare(strict_types=1);

/**
 * RateLimiter
 * Sliding-window-ish fixed-decay rate limiter backed by a PDO table.
 * Used to throttle login attempts, password-reset requests, OTP
 * verification attempts, etc., per key (e.g. "login:ip:1.2.3.4" or
 * "login:email:user@example.com").
 *
 * Required table (MySQL):
 *
 * CREATE TABLE rate_limits (
 *   `key` VARCHAR(191) NOT NULL PRIMARY KEY,
 *   attempts INT UNSIGNED NOT NULL DEFAULT 0,
 *   first_attempt_at DATETIME NOT NULL,
 *   last_attempt_at DATETIME NOT NULL,
 *   blocked_until DATETIME NULL,
 *   INDEX (blocked_until)
 * ) ENGINE=InnoDB;
 */
final class RateLimiter
{
    private PDO $pdo;

    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * Record an attempt for $key. Returns true if the caller is currently
     * blocked (should NOT proceed), false if allowed to proceed.
     */
    public function tooManyAttempts(string $key, int $maxAttempts, int $decayMinutes): bool
    {
        $row = $this->fetch($key);
        $now = new DateTimeImmutable();

        if ($row === null) {
            return false;
        }

        if ($row['blocked_until'] !== null && new DateTimeImmutable($row['blocked_until']) > $now) {
            return true;
        }

        $decayWindowStart = $now->modify("-{$decayMinutes} minutes");
        if (new DateTimeImmutable($row['first_attempt_at']) < $decayWindowStart) {
            // Window expired naturally; reset the counter.
            $this->clear($key);
            return false;
        }

        return $row['attempts'] >= $maxAttempts;
    }

    /** Register a new failed attempt; blocks further attempts once threshold is hit. */
    public function hit(string $key, int $maxAttempts, int $decayMinutes): int
    {
        $now = new DateTimeImmutable();
        $row = $this->fetch($key);

        if ($row === null) {
            $stmt = $this->pdo->prepare(
                'INSERT INTO rate_limits (`key`, attempts, first_attempt_at, last_attempt_at, blocked_until)
                 VALUES (:key, 1, :now, :now, NULL)'
            );
            $stmt->execute(['key' => $key, 'now' => $now->format('Y-m-d H:i:s')]);
            return 1;
        }

        $decayWindowStart = $now->modify("-{$decayMinutes} minutes");
        if (new DateTimeImmutable($row['first_attempt_at']) < $decayWindowStart) {
            // Start a fresh window.
            $stmt = $this->pdo->prepare(
                'UPDATE rate_limits SET attempts = 1, first_attempt_at = :now, last_attempt_at = :now, blocked_until = NULL
                 WHERE `key` = :key'
            );
            $stmt->execute(['key' => $key, 'now' => $now->format('Y-m-d H:i:s')]);
            return 1;
        }

        $attempts = $row['attempts'] + 1;
        $blockedUntil = null;
        if ($attempts >= $maxAttempts) {
            // Exponential-ish backoff: block longer the more repeated the abuse.
            $blockMinutes = min(60, $decayMinutes * (int) (1 + floor(($attempts - $maxAttempts) / max(1, $maxAttempts))));
            $blockedUntil = $now->modify('+' . max($decayMinutes, $blockMinutes) . ' minutes')->format('Y-m-d H:i:s');
        }

        $stmt = $this->pdo->prepare(
            'UPDATE rate_limits SET attempts = :attempts, last_attempt_at = :now, blocked_until = :blocked
             WHERE `key` = :key'
        );
        $stmt->execute([
            'attempts' => $attempts,
            'now'      => $now->format('Y-m-d H:i:s'),
            'blocked'  => $blockedUntil,
            'key'      => $key,
        ]);

        return $attempts;
    }

    /** Clear attempts for a key (call on successful login, etc). */
    public function clear(string $key): void
    {
        $stmt = $this->pdo->prepare('DELETE FROM rate_limits WHERE `key` = :key');
        $stmt->execute(['key' => $key]);
    }

    /** Seconds remaining until the key is unblocked (0 if not blocked). */
    public function availableIn(string $key): int
    {
        $row = $this->fetch($key);
        if ($row === null || $row['blocked_until'] === null) {
            return 0;
        }
        $diff = (new DateTimeImmutable($row['blocked_until']))->getTimestamp() - time();
        return max(0, $diff);
    }

    private function fetch(string $key): ?array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM rate_limits WHERE `key` = :key LIMIT 1');
        $stmt->execute(['key' => $key]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    /** Build a consistent rate-limit key from an action + identifier. */
    public static function makeKey(string $action, string $identifier): string
    {
        return $action . ':' . hash('sha256', strtolower($identifier));
    }
}
