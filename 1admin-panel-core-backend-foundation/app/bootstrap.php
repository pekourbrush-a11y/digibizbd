<?php
/**
 * =====================================================================
 * bootstrap.php
 * ---------------------------------------------------------------------
 * Single entry point that wires up the backend foundation.
 *
 * USAGE — add this ONE line at the very top of any PHP file inside
 * public_html that needs the database, helpers, or JSON responses:
 *
 *   require_once __DIR__ . '/../app/bootstrap.php';
 *
 * (Adjust the number of ../ depending on how deep the file is.)
 *
 * This file does not output anything, redirect anyone, or touch any
 * existing HTML/CSS/JS. It only prepares the PHP environment. It also
 * contains NO authentication/login logic.
 * =====================================================================
 */

declare(strict_types=1);

define('APP_BOOTSTRAPPED', true);

/* --------------------------------------------------------------------
 * 1. CORE FILES (order matters)
 * ------------------------------------------------------------------ */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/autoload.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/response.php';
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/functions.php';

/* --------------------------------------------------------------------
 * 2. TIMEZONE
 * ------------------------------------------------------------------ */
date_default_timezone_set(APP_TIMEZONE);

/* --------------------------------------------------------------------
 * 3. SECURE SESSION CONFIGURATION (generic hardening only — this is
 * NOT a login system; it only makes whatever session usage you already
 * have, or will add later, safer by default).
 * ------------------------------------------------------------------ */
if (session_status() === PHP_SESSION_NONE) {
    session_name(SESSION_NAME);

    session_set_cookie_params([
        'lifetime' => SESSION_LIFETIME_SECONDS,
        'path'     => '/',
        'domain'   => '',
        'secure'   => SESSION_COOKIE_SECURE,
        'httponly' => SESSION_COOKIE_HTTPONLY,
        'samesite' => SESSION_COOKIE_SAMESITE,
    ]);

    ini_set('session.use_strict_mode', '1');
    ini_set('session.gc_maxlifetime', (string) SESSION_LIFETIME_SECONDS);

    session_start();
}

/* --------------------------------------------------------------------
 * 4. GLOBAL ERROR / EXCEPTION HANDLING
 * Logs everything server-side; never leaks internals to the browser.
 * ------------------------------------------------------------------ */
ini_set('log_errors', '1');
ini_set('error_log', LOG_PATH . '/php_errors.log');

set_error_handler(function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    error_log(sprintf('[PHP ERROR] %s in %s:%d', $message, $file, $line));

    if (APP_DEBUG) {
        return false;
    }
    return true;
});

set_exception_handler(function (Throwable $e): void {
    error_log(sprintf(
        '[UNCAUGHT EXCEPTION] %s in %s:%d | Trace: %s',
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        $e->getTraceAsString()
    ));

    if (!headers_sent()) {
        http_response_code(500);
    }

    if (APP_DEBUG) {
        echo '<pre>' . htmlspecialchars((string) $e) . '</pre>';
        return;
    }

    if (function_exists('request_wants_json') && request_wants_json()) {
        Response::serverError('An unexpected error occurred. Please try again later.');
    }

    echo 'An unexpected error occurred. Please try again later.';
});

register_shutdown_function(function (): void {
    $error = error_get_last();
    if ($error !== null && in_array($error['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
        error_log(sprintf(
            '[FATAL ERROR] %s in %s:%d',
            $error['message'],
            $error['file'],
            $error['line']
        ));
    }
});

/* --------------------------------------------------------------------
 * 5. BASIC SECURITY HEADERS (safe, non-breaking)
 * ------------------------------------------------------------------ */
if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: strict-origin-when-cross-origin');
}

/* --------------------------------------------------------------------
 * 6. STORAGE DIRECTORIES
 * ------------------------------------------------------------------ */
if (!is_dir(LOG_PATH)) {
    @mkdir(LOG_PATH, 0755, true);
}
