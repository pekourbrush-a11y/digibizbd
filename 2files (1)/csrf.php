<?php
declare(strict_types=1);

require_once __DIR__ . '/session.php';

/**
 * CSRF
 * Synchronizer-token pattern CSRF protection with per-token expiry
 * and constant-time comparison. Tokens are stored keyed by "action"
 * so multiple forms on a page can have independent tokens.
 */
final class CSRF
{
    private const SESSION_KEY = '_csrf_tokens';
    private const TOKEN_TTL = 3600; // 1 hour
    private const MAX_TOKENS = 20;  // cap stored tokens per session

    /** Generate (or reuse a still-valid) token for a given action/form. */
    public static function generateToken(string $action = 'default'): string
    {
        SessionManager::start();
        $tokens = $_SESSION[self::SESSION_KEY] ?? [];

        if (isset($tokens[$action]) && $tokens[$action]['expires'] > time()) {
            return $tokens[$action]['token'];
        }

        $token = bin2hex(random_bytes(32));
        $tokens[$action] = [
            'token'   => $token,
            'expires' => time() + self::TOKEN_TTL,
        ];

        // Prevent unbounded growth from many distinct action names.
        if (count($tokens) > self::MAX_TOKENS) {
            array_shift($tokens);
        }

        $_SESSION[self::SESSION_KEY] = $tokens;
        return $token;
    }

    public static function getToken(string $action = 'default'): string
    {
        return self::generateToken($action);
    }

    /** Verify a submitted token. Optionally consume (single-use) it. */
    public static function verifyToken(?string $submitted, string $action = 'default', bool $consume = true): bool
    {
        SessionManager::start();
        if ($submitted === null || $submitted === '') {
            return false;
        }

        $tokens = $_SESSION[self::SESSION_KEY] ?? [];
        if (!isset($tokens[$action])) {
            return false;
        }

        $entry = $tokens[$action];
        $valid = $entry['expires'] > time() && hash_equals($entry['token'], $submitted);

        if ($consume) {
            unset($_SESSION[self::SESSION_KEY][$action]);
        }

        return $valid;
    }

    /** Convenience: verify token from request superglobals (POST/headers). */
    public static function verifyRequest(string $action = 'default', bool $consume = true): bool
    {
        $token = $_POST['csrf_token']
            ?? $_SERVER['HTTP_X_CSRF_TOKEN']
            ?? null;
        return self::verifyToken($token, $action, $consume);
    }

    /** Output a ready-to-use hidden input field for HTML forms. */
    public static function field(string $action = 'default'): string
    {
        $token = htmlspecialchars(self::generateToken($action), ENT_QUOTES, 'UTF-8');
        return '<input type="hidden" name="csrf_token" value="' . $token . '">';
    }

    public static function clear(string $action = 'default'): void
    {
        SessionManager::start();
        unset($_SESSION[self::SESSION_KEY][$action]);
    }
}
