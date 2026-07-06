<?php
declare(strict_types=1);

/**
 * Sanitizer
 * Centralized input sanitization helpers to mitigate XSS, injection,
 * and malformed-data issues. Use in combination with Validator, which
 * checks correctness; Sanitizer normalizes/cleans values.
 */
final class Sanitizer
{
    private function __construct() {}

    /** Trim, strip null bytes and control chars from a scalar string. */
    public static function cleanString(?string $value): string
    {
        if ($value === null) {
            return '';
        }
        $value = str_replace("\0", '', $value);
        $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $value) ?? '';
        return trim($value);
    }

    /** Escape a string for safe HTML output (XSS protection). */
    public static function escapeHtml(?string $value): string
    {
        return htmlspecialchars(self::cleanString($value), ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    /** Strip all HTML/PHP tags from a string. */
    public static function stripTags(?string $value, string $allowedTags = ''): string
    {
        return trim(strip_tags(self::cleanString($value), $allowedTags));
    }

    /** Remove any script/event-handler style payloads from rich text before storage. */
    public static function removeXss(?string $value): string
    {
        $value = self::cleanString($value);
        $value = preg_replace('/<\s*script[^>]*>.*?<\s*\/\s*script\s*>/is', '', $value) ?? $value;
        $value = preg_replace('/<\s*iframe[^>]*>.*?<\s*\/\s*iframe\s*>/is', '', $value) ?? $value;
        $value = preg_replace('/on\w+\s*=\s*(".*?"|\'.*?\'|[^\s>]+)/i', '', $value) ?? $value;
        $value = preg_replace('/javascript\s*:/i', '', $value) ?? $value;
        $value = preg_replace('/data\s*:\s*text\/html/i', '', $value) ?? $value;
        return $value;
    }

    /** Normalize and validate-clean an email address. */
    public static function cleanEmail(?string $value): string
    {
        $value = strtolower(self::cleanString($value));
        $filtered = filter_var($value, FILTER_SANITIZE_EMAIL);
        return $filtered !== false ? $filtered : '';
    }

    public static function cleanInt(mixed $value, int $default = 0): int
    {
        if (is_numeric($value)) {
            return (int) $value;
        }
        $filtered = filter_var($value, FILTER_SANITIZE_NUMBER_INT);
        return $filtered !== false && $filtered !== '' ? (int) $filtered : $default;
    }

    public static function cleanFloat(mixed $value, float $default = 0.0): float
    {
        $filtered = filter_var($value, FILTER_SANITIZE_NUMBER_FLOAT, FILTER_FLAG_ALLOW_FRACTION);
        return $filtered !== false && $filtered !== '' ? (float) $filtered : $default;
    }

    public static function cleanBool(mixed $value): bool
    {
        return filter_var($value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) === true;
    }

    /** Safe filename: strips path traversal and unsafe characters. */
    public static function cleanFilename(?string $value): string
    {
        $value = self::cleanString($value);
        $value = basename($value);
        $value = preg_replace('/[^A-Za-z0-9._-]/', '_', $value) ?? '';
        return ltrim($value, '.-');
    }

    /** Validate/clean a URL, rejecting dangerous schemes (javascript:, data:, etc). */
    public static function cleanUrl(?string $value): string
    {
        $value = self::cleanString($value);
        $filtered = filter_var($value, FILTER_SANITIZE_URL);
        if ($filtered === false) {
            return '';
        }
        if (!preg_match('#^https?://#i', $filtered)) {
            return '';
        }
        return $filtered;
    }

    /** Recursively sanitize an array of strings using a supplied callback. */
    public static function cleanArray(array $data, callable $cleaner = null): array
    {
        $cleaner = $cleaner ?? [self::class, 'cleanString'];
        $out = [];
        foreach ($data as $key => $value) {
            $key = self::cleanString((string) $key);
            if (is_array($value)) {
                $out[$key] = self::cleanArray($value, $cleaner);
            } else {
                $out[$key] = $cleaner($value);
            }
        }
        return $out;
    }

    /** Strip anything but digits — useful for phone numbers, OTP codes, etc. */
    public static function digitsOnly(?string $value): string
    {
        return preg_replace('/\D+/', '', (string) $value) ?? '';
    }

    /** Normalize whitespace-only-safe alphanumeric identifiers (usernames, slugs). */
    public static function cleanSlug(?string $value): string
    {
        $value = strtolower(self::cleanString($value));
        $value = preg_replace('/[^a-z0-9-_]+/', '-', $value) ?? '';
        return trim($value, '-');
    }
}
