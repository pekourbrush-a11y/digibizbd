<?php
/**
 * =====================================================================
 * helpers.php
 * ---------------------------------------------------------------------
 * General-purpose utility functions with NO database dependency.
 *
 * SCOPE: Sanitisation, generic tokens, CSRF, request/client info, date
 * formatting, and flash messages. Deliberately excludes anything
 * related to login, password verification, or user sessions tied to
 * authentication — that belongs to a future Authentication module.
 * =====================================================================
 */

if (!defined('APP_BOOTSTRAPPED')) {
    http_response_code(403);
    exit('Direct access forbidden.');
}

/* --------------------------------------------------------------------
 * INPUT SANITISATION / VALIDATION
 * ------------------------------------------------------------------ */

function sanitize_input(mixed $value): mixed
{
    if (is_array($value)) {
        return array_map('sanitize_input', $value);
    }
    if (!is_string($value)) {
        return $value;
    }
    return trim(strip_tags($value));
}

/**
 * HTML-escape a string for safe output.
 */
function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

function is_valid_email(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/* --------------------------------------------------------------------
 * GENERIC TOKENS / RANDOMNESS (not tied to login/session auth)
 * ------------------------------------------------------------------ */

function generate_random_token(int $bytes = 32): string
{
    return bin2hex(random_bytes($bytes));
}

function generate_uuid_v4(): string
{
    $data = random_bytes(16);
    $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
    $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

/**
 * HMAC-hash a token before storing it in the database. Useful any time
 * you need to store a verifiable-but-not-reversible token (invite
 * links, generic one-time links, etc.).
 */
function hash_token(string $rawToken): string
{
    return hash_hmac('sha256', $rawToken, APP_SECRET_KEY);
}

/* --------------------------------------------------------------------
 * CSRF PROTECTION (generic form-protection, not login-specific)
 * ------------------------------------------------------------------ */

function generate_csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = generate_random_token(32);
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token(?string $token): bool
{
    if (empty($_SESSION['csrf_token']) || empty($token)) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $token);
}

/* --------------------------------------------------------------------
 * REQUEST / CLIENT INFO
 * ------------------------------------------------------------------ */

function get_client_ip(): string
{
    $headers = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'REMOTE_ADDR'];

    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ipList = explode(',', $_SERVER[$header]);
            $ip = trim($ipList[0]);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }
    return '0.0.0.0';
}

function get_user_agent(): string
{
    return substr($_SERVER['HTTP_USER_AGENT'] ?? 'unknown', 0, 255);
}

function is_ajax_request(): bool
{
    return isset($_SERVER['HTTP_X_REQUESTED_WITH'])
        && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
}

function request_wants_json(): bool
{
    return is_ajax_request()
        || (isset($_SERVER['HTTP_ACCEPT']) && str_contains($_SERVER['HTTP_ACCEPT'], 'application/json'))
        || (isset($_SERVER['CONTENT_TYPE']) && str_contains($_SERVER['CONTENT_TYPE'], 'application/json'));
}

/**
 * Read and JSON-decode the raw request body.
 */
function get_json_body(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return [];
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : [];
}

/* --------------------------------------------------------------------
 * DATE / TIME
 * ------------------------------------------------------------------ */

function now_datetime(): string
{
    return (new DateTime('now', new DateTimeZone(APP_TIMEZONE)))->format('Y-m-d H:i:s');
}

function format_date(string $datetime, string $format = 'd M Y, h:i A'): string
{
    try {
        $dt = new DateTime($datetime, new DateTimeZone(APP_TIMEZONE));
        return $dt->format($format);
    } catch (Exception) {
        return $datetime;
    }
}

/* --------------------------------------------------------------------
 * REDIRECT / FLASH MESSAGES (generic session helpers)
 * ------------------------------------------------------------------ */

function redirect_to(string $url): never
{
    header('Location: ' . $url, true, 302);
    exit;
}

function flash_set(string $key, mixed $value): void
{
    $_SESSION['_flash'][$key] = $value;
}

function flash_get(string $key, mixed $default = null): mixed
{
    $value = $_SESSION['_flash'][$key] ?? $default;
    unset($_SESSION['_flash'][$key]);
    return $value;
}

/* --------------------------------------------------------------------
 * MISC
 * ------------------------------------------------------------------ */

function array_get(array $array, string $key, mixed $default = null): mixed
{
    return $array[$key] ?? $default;
}
