<?php
declare(strict_types=1);

/**
 * Security
 * Cross-cutting security helpers: HTTP security headers, CSP nonce
 * generation, output escaping, and misc hardening utilities.
 */
final class Security
{
    /** Emit standard hardened security headers. Call early, before any output. */
    public static function setSecurityHeaders(?string $cspNonce = null): void
    {
        if (headers_sent()) {
            return;
        }

        $nonce = $cspNonce ?? self::generateNonce();

        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('Permissions-Policy: geolocation=(), microphone=(), camera=(), payment=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header(sprintf(
            "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-%s'; " .
            "style-src 'self' 'nonce-%s'; img-src 'self' data:; object-src 'none'; " .
            "base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
            $nonce,
            $nonce
        ));

        if (self::isHttps()) {
            header('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload');
        }
    }

    public static function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['SERVER_PORT'] ?? null) == 443)
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
    }

    /** Generate a per-request nonce for inline <script nonce="..."> / <style nonce="...">. */
    public static function generateNonce(): string
    {
        static $nonce = null;
        if ($nonce === null) {
            $nonce = base64_encode(random_bytes(16));
        }
        return $nonce;
    }

    /** Escape a value for safe HTML output. */
    public static function escape(?string $value): string
    {
        return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    /** Escape a value for safe use inside a JS context (e.g. inline JSON). */
    public static function escapeJs(mixed $value): string
    {
        return json_encode($value, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_SLASHES) ?: 'null';
    }

    /** Escape a value for safe use inside a URL query component. */
    public static function escapeUrl(?string $value): string
    {
        return rawurlencode((string) $value);
    }

    /** Constant-time string comparison wrapper (avoids timing attacks). */
    public static function timingSafeEquals(string $known, string $given): bool
    {
        return hash_equals($known, $given);
    }

    /** Generate a cryptographically secure random token (hex). */
    public static function randomToken(int $bytes = 32): string
    {
        return bin2hex(random_bytes($bytes));
    }

    /** Basic same-origin check for Referer/Origin headers (extra CSRF defense-in-depth). */
    public static function isSameOrigin(): bool
    {
        $origin = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? null;
        if ($origin === null) {
            return false;
        }
        $host = $_SERVER['HTTP_HOST'] ?? '';
        $originHost = parse_url($origin, PHP_URL_HOST) ?? '';
        return hash_equals(strtolower($host), strtolower((string) $originHost));
    }

    /** Reject requests carrying disallowed content types for POST bodies (defense-in-depth). */
    public static function assertJsonOrFormContentType(): bool
    {
        $type = $_SERVER['CONTENT_TYPE'] ?? '';
        return $type === '' ||
            stripos($type, 'application/x-www-form-urlencoded') === 0 ||
            stripos($type, 'multipart/form-data') === 0 ||
            stripos($type, 'application/json') === 0;
    }

    /** Redact sensitive fields before writing request data to logs. */
    public static function redactForLogging(array $data, array $sensitiveKeys = ['password', 'password_confirmation', 'token', 'secret', 'totp_code']): array
    {
        foreach ($data as $key => $value) {
            if (in_array(strtolower((string) $key), $sensitiveKeys, true)) {
                $data[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $data[$key] = self::redactForLogging($value, $sensitiveKeys);
            }
        }
        return $data;
    }
}
