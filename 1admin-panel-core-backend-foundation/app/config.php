<?php
/**
 * =====================================================================
 * config.php
 * ---------------------------------------------------------------------
 * Core configuration for the Admin Panel backend foundation.
 *
 * SCOPE: This is infrastructure-only configuration (database, app
 * constants, storage paths, error reporting). It intentionally
 * contains NO authentication, session-login, or user-credential
 * settings — those belong to a future Authentication module.
 *
 * SECURITY: Keep this file OUTSIDE public_html (see README_DEPLOYMENT.md).
 * =====================================================================
 */

if (!defined('APP_BOOTSTRAPPED')) {
    http_response_code(403);
    exit('Direct access forbidden.');
}

/* --------------------------------------------------------------------
 * ENVIRONMENT
 * ------------------------------------------------------------------ */
define('APP_ENV', 'production');   // 'production' or 'development'
define('APP_DEBUG', false);        // Never true in production.

/* --------------------------------------------------------------------
 * APPLICATION
 * ------------------------------------------------------------------ */
define('APP_NAME', 'Admin Panel');
define('APP_URL', 'https://yourdomain.com');   // TODO: set your real domain
define('APP_TIMEZONE', 'UTC');                 // TODO: change if needed, e.g. 'Asia/Dhaka'

/* --------------------------------------------------------------------
 * DATABASE (cPanel / MySQL)
 * TODO: Replace these with your actual cPanel database credentials.
 * ------------------------------------------------------------------ */
define('DB_DRIVER', 'mysql');
define('DB_HOST', 'localhost');
define('DB_PORT', '3306');
define('DB_NAME', 'your_database_name');
define('DB_USER', 'your_database_user');
define('DB_PASS', 'your_database_password');
define('DB_CHARSET', 'utf8mb4');

/* --------------------------------------------------------------------
 * SECURITY (generic, non-auth utilities: CSRF, hashing salts, etc.)
 * ------------------------------------------------------------------ */
// Used to HMAC-sign tokens (CSRF tokens, generic one-time tokens, etc.)
// Generate a real value with: php -r "echo bin2hex(random_bytes(32));"
define('APP_SECRET_KEY', 'CHANGE_THIS_TO_A_RANDOM_64_CHAR_HEX_STRING_BEFORE_GOING_LIVE');

/* --------------------------------------------------------------------
 * SESSION (generic PHP session hardening only — no login/auth logic)
 * ------------------------------------------------------------------ */
define('SESSION_NAME', 'admin_panel_sid');
define('SESSION_LIFETIME_SECONDS', 60 * 60 * 2); // 2 hours
define('SESSION_COOKIE_SECURE', true);   // requires HTTPS — keep true on live site
define('SESSION_COOKIE_HTTPONLY', true);
define('SESSION_COOKIE_SAMESITE', 'Lax');

/* --------------------------------------------------------------------
 * FILE STORAGE
 * ------------------------------------------------------------------ */
define('STORAGE_PATH', dirname(__DIR__) . '/storage');
define('LOG_PATH', STORAGE_PATH . '/logs');

/* --------------------------------------------------------------------
 * ERROR REPORTING (handlers wired up in bootstrap.php)
 * ------------------------------------------------------------------ */
if (APP_ENV === 'production') {
    error_reporting(E_ALL);
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
} else {
    error_reporting(E_ALL);
    ini_set('display_errors', '1');
    ini_set('log_errors', '1');
}
