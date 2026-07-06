<?php
declare(strict_types=1);

/**
 * SessionManager
 * Hardened session handling: secure cookie flags, strict mode,
 * ID regeneration, fingerprinting, idle/absolute timeouts, flash data.
 */
final class SessionManager
{
    private static bool $started = false;

    public const IDLE_TIMEOUT_SECONDS = 900;      // 15 minutes
    public const ABSOLUTE_TIMEOUT_SECONDS = 28800; // 8 hours

    public static function start(): void
    {
        if (self::$started || session_status() === PHP_SESSION_ACTIVE) {
            self::$started = true;
            return;
        }

        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['SERVER_PORT'] ?? null) == 443)
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');

        session_name('__Host_SECSESSID');
        // __Host- prefix requires Secure, Path=/, no Domain attribute.
        if (!$isHttps) {
            // Fall back to a non-prefixed name in local/dev http environments,
            // since __Host- cookies are rejected without HTTPS.
            session_name('SECSESSID');
        }

        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.sid_length', '48');
        ini_set('session.sid_bits_per_character', '6');
        ini_set('session.gc_maxlifetime', (string) self::ABSOLUTE_TIMEOUT_SECONDS);

        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => '',
            'secure'   => $isHttps,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);

        session_start();
        self::$started = true;

        self::enforceFingerprint();
        self::enforceTimeouts();
    }

    /** Bind the session to a hash of IP + User-Agent to reduce session hijacking risk. */
    private static function enforceFingerprint(): void
    {
        $fingerprint = hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? '') . '|' . ($_SERVER['HTTP_USER_AGENT'] ?? ''));

        if (!isset($_SESSION['_fingerprint'])) {
            $_SESSION['_fingerprint'] = $fingerprint;
            return;
        }

        if (!hash_equals($_SESSION['_fingerprint'], $fingerprint)) {
            self::destroy();
            session_start();
            $_SESSION['_fingerprint'] = $fingerprint;
        }
    }

    private static function enforceTimeouts(): void
    {
        $now = time();

        if (isset($_SESSION['_last_activity']) && ($now - $_SESSION['_last_activity']) > self::IDLE_TIMEOUT_SECONDS) {
            self::destroy();
            session_start();
        }

        if (!isset($_SESSION['_started_at'])) {
            $_SESSION['_started_at'] = $now;
        } elseif (($now - $_SESSION['_started_at']) > self::ABSOLUTE_TIMEOUT_SECONDS) {
            self::destroy();
            session_start();
            $_SESSION['_started_at'] = $now;
        }

        $_SESSION['_last_activity'] = $now;

        // Periodic ID rotation to limit session fixation window.
        if (!isset($_SESSION['_regenerated_at'])) {
            $_SESSION['_regenerated_at'] = $now;
        } elseif (($now - $_SESSION['_regenerated_at']) > 300) {
            self::regenerate();
        }
    }

    public static function regenerate(bool $deleteOld = true): void
    {
        self::start();
        session_regenerate_id($deleteOld);
        $_SESSION['_regenerated_at'] = time();
    }

    public static function set(string $key, mixed $value): void
    {
        self::start();
        $_SESSION[$key] = $value;
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        self::start();
        return $_SESSION[$key] ?? $default;
    }

    public static function has(string $key): bool
    {
        self::start();
        return isset($_SESSION[$key]);
    }

    public static function remove(string $key): void
    {
        self::start();
        unset($_SESSION[$key]);
    }

    /** Set a one-time flash value, readable once via getFlash(). */
    public static function setFlash(string $key, mixed $value): void
    {
        self::start();
        $_SESSION['_flash'][$key] = $value;
    }

    public static function getFlash(string $key, mixed $default = null): mixed
    {
        self::start();
        $value = $_SESSION['_flash'][$key] ?? $default;
        unset($_SESSION['_flash'][$key]);
        return $value;
    }

    public static function destroy(): void
    {
        self::start();
        $_SESSION = [];

        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires'  => time() - 42000,
                'path'     => $params['path'],
                'domain'   => $params['domain'],
                'secure'   => $params['secure'],
                'httponly' => $params['httponly'],
                'samesite' => $params['samesite'] ?? 'Strict',
            ]);
        }

        session_destroy();
        self::$started = false;
    }
}
