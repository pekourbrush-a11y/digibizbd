<?php
declare(strict_types=1);

/**
 * Password
 * Secure password hashing (Argon2id preferred, bcrypt fallback),
 * verification, rehash detection, strength validation, and
 * cryptographically secure random password generation.
 */
final class Password
{
    private const ARGON2ID_OPTIONS = [
        'memory_cost' => 65536, // 64 MB
        'time_cost'   => 4,
        'threads'     => 2,
    ];

    private const BCRYPT_OPTIONS = [
        'cost' => 12,
    ];

    private static array $commonPasswords = [
        'password', 'password1', '123456', '12345678', 'qwerty', 'letmein',
        'admin', 'welcome', 'monkey', 'football', 'iloveyou', 'abc123',
        'passw0rd', '123456789', '1234567890',
    ];

    public static function algorithm(): string
    {
        return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
    }

    public static function hash(string $plainPassword): string
    {
        $algo = self::algorithm();
        $options = $algo === (defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : null)
            ? self::ARGON2ID_OPTIONS
            : self::BCRYPT_OPTIONS;

        $hash = password_hash($plainPassword, $algo, $options);
        if ($hash === false) {
            throw new RuntimeException('Password hashing failed.');
        }
        return $hash;
    }

    public static function verify(string $plainPassword, string $hash): bool
    {
        if ($hash === '') {
            return false;
        }
        return password_verify($plainPassword, $hash);
    }

    public static function needsRehash(string $hash): bool
    {
        $algo = self::algorithm();
        $options = $algo === (defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : null)
            ? self::ARGON2ID_OPTIONS
            : self::BCRYPT_OPTIONS;
        return password_needs_rehash($hash, $algo, $options);
    }

    /**
     * Validate password strength policy.
     * Returns an array of violation messages; empty array means the password passes.
     */
    public static function validateStrength(string $plainPassword, array $context = []): array
    {
        $errors = [];

        if (mb_strlen($plainPassword) < 8) {
            $errors[] = 'Password must be at least 8 characters long.';
        }
        if (mb_strlen($plainPassword) > 128) {
            $errors[] = 'Password must not exceed 128 characters.';
        }
        if (!preg_match('/[A-Z]/', $plainPassword)) {
            $errors[] = 'Password must include at least one uppercase letter.';
        }
        if (!preg_match('/[a-z]/', $plainPassword)) {
            $errors[] = 'Password must include at least one lowercase letter.';
        }
        if (!preg_match('/[0-9]/', $plainPassword)) {
            $errors[] = 'Password must include at least one number.';
        }
        if (!preg_match('/[^A-Za-z0-9]/', $plainPassword)) {
            $errors[] = 'Password must include at least one special character.';
        }
        if (in_array(strtolower($plainPassword), self::$commonPasswords, true)) {
            $errors[] = 'This password is too common. Please choose a stronger one.';
        }

        // Reject passwords containing the user's own identifying info.
        foreach (['email', 'username', 'name'] as $field) {
            if (!empty($context[$field]) && stripos($plainPassword, (string) $context[$field]) !== false) {
                $errors[] = 'Password must not contain your personal information.';
                break;
            }
        }

        return $errors;
    }

    public static function isStrong(string $plainPassword, array $context = []): bool
    {
        return empty(self::validateStrength($plainPassword, $context));
    }

    /** Generate a cryptographically secure random password (useful for temp passwords). */
    public static function generateRandom(int $length = 16): string
    {
        $length = max(12, $length);
        $upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
        $lower = 'abcdefghijkmnopqrstuvwxyz';
        $digits = '23456789';
        $special = '!@#$%^&*()-_=+[]{}';
        $all = $upper . $lower . $digits . $special;

        $password = [
            $upper[random_int(0, strlen($upper) - 1)],
            $lower[random_int(0, strlen($lower) - 1)],
            $digits[random_int(0, strlen($digits) - 1)],
            $special[random_int(0, strlen($special) - 1)],
        ];

        for ($i = count($password); $i < $length; $i++) {
            $password[] = $all[random_int(0, strlen($all) - 1)];
        }

        shuffle($password);
        return implode('', $password);
    }
}
