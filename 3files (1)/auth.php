<?php
declare(strict_types=1);

/**
 * api/auth.php
 *
 * Authentication endpoints AND the shared API kernel used by every other
 * file in api/. Other api/*.php files `require_once __DIR__.'/auth.php'`
 * to get: DB access, JSON helpers, auth/role/CSRF guards, and a global
 * exception handler. The auth *routing* below only runs when this file
 * is the directly-requested script (front-controller pattern), so
 * including it from other endpoints is side-effect free.
 *
 * -------------------------------------------------------------------
 * Endpoints (all responses are JSON):
 *
 *   GET  /api/auth.php?action=csrf-token   -> { success, csrf_token }
 *   GET  /api/auth.php?action=me           -> { success, user }               [auth required]
 *   POST /api/auth.php?action=register     { name, email, password }
 *   POST /api/auth.php?action=login        { email, password, remember }
 *   POST /api/auth.php?action=verify-2fa   { totp_code | backup_code }
 *   POST /api/auth.php?action=logout                                          [auth required, CSRF]
 * -------------------------------------------------------------------
 */

require_once __DIR__ . '/../session.php';
require_once __DIR__ . '/../security.php';
require_once __DIR__ . '/../csrf.php';
require_once __DIR__ . '/../sanitizer.php';
require_once __DIR__ . '/../validator.php';
require_once __DIR__ . '/../password.php';
require_once __DIR__ . '/../two_factor.php';
require_once __DIR__ . '/../rate_limiter.php';
require_once __DIR__ . '/../remember_me.php';
require_once __DIR__ . '/../auth.php';

// ---------------------------------------------------------------------------
// API kernel (shared by every api/*.php file)
// ---------------------------------------------------------------------------

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
Security::setSecurityHeaders();
SessionManager::start();

/** Lazily-constructed shared PDO connection for the whole request. */
function get_pdo(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $host = getenv('DB_HOST') ?: '127.0.0.1';
        $name = getenv('DB_NAME') ?: 'app';
        $user = getenv('DB_USER') ?: 'app';
        $pass = getenv('DB_PASS') ?: '';
        $pdo = new PDO("mysql:host={$host};dbname={$name};charset=utf8mb4", $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }
    return $pdo;
}

function current_auth(): Auth
{
    static $auth = null;
    if ($auth === null) {
        $auth = new Auth(get_pdo());
    }
    return $auth;
}

/** Emit a JSON payload and terminate the request. */
function json_response(array $payload, int $status = 200): never
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    exit;
}

function json_ok(array $data = [], int $status = 200): never
{
    json_response(array_merge(['success' => true], $data), $status);
}

function json_error(string $message, int $status = 400, array $extra = []): never
{
    json_response(array_merge(['success' => false, 'error' => $message], $extra), $status);
}

/** Parse a JSON request body, falling back to $_POST for form-encoded clients. */
function json_input(): array
{
    $raw = file_get_contents('php://input') ?: '';
    if ($raw !== '') {
        $decoded = json_decode($raw, true);
        if (is_array($decoded)) {
            return $decoded;
        }
    }
    return $_POST;
}

/** Require an authenticated user (session or remember-me cookie). Halts with 401 otherwise. */
function require_auth(): array
{
    $auth = current_auth();
    if (!$auth->isAuthenticated() && !$auth->attemptRememberMeLogin()) {
        json_error('Authentication required.', 401);
    }
    $user = $auth->user();
    if ($user === null) {
        json_error('Authentication required.', 401);
    }
    return $user;
}

/** Require a specific role on the `users.role` column (default 'user'). Halts with 403. */
function require_role(array $user, string $role): void
{
    if (($user['role'] ?? 'user') !== $role) {
        json_error('You do not have permission to perform this action.', 403);
    }
}

/** CSRF guard for state-changing verbs, using the X-CSRF-Token header. */
function require_csrf(): void
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
        return;
    }
    $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ($_POST['csrf_token'] ?? null);
    if (!CSRF::verifyToken($token, 'api', false)) {
        json_error('Invalid or missing CSRF token.', 419);
    }
}

/** Restrict which HTTP methods an endpoint accepts. */
function require_method(string ...$methods): void
{
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    if (!in_array($method, $methods, true)) {
        json_error('Method not allowed.', 405);
    }
}

/** Read a positive-integer pagination param, clamped to sane bounds. */
function paginate_params(int $defaultLimit = 20, int $maxLimit = 100): array
{
    $page = max(1, Sanitizer::cleanInt($_GET['page'] ?? 1, 1));
    $limit = Sanitizer::cleanInt($_GET['limit'] ?? $defaultLimit, $defaultLimit);
    $limit = max(1, min($maxLimit, $limit));
    return ['page' => $page, 'limit' => $limit, 'offset' => ($page - 1) * $limit];
}

/**
 * Best-effort login attempt audit log (see api/login-history.php for schema
 * and the read endpoint). Failures here never interrupt the auth flow.
 */
function log_login_attempt(?int $userId, string $status): void
{
    try {
        $stmt = get_pdo()->prepare(
            'INSERT INTO login_history (user_id, ip_address, user_agent, status, created_at)
             VALUES (:uid, :ip, :ua, :status, NOW())'
        );
        $stmt->execute([
            'uid'    => $userId,
            'ip'     => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
            'ua'     => substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255),
            'status' => $status,
        ]);
    } catch (Throwable $e) {
        error_log('[api] login_history insert skipped: ' . $e->getMessage());
    }
}

set_exception_handler(static function (Throwable $e): void {
    error_log('[api] ' . get_class($e) . ': ' . $e->getMessage());
    if (!headers_sent()) {
        json_error('An unexpected error occurred.', 500);
    }
});

// ---------------------------------------------------------------------------
// Auth routing (only executes when this file is requested directly)
// ---------------------------------------------------------------------------

$__isEntryPoint = isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === __FILE__;

if ($__isEntryPoint) {
    $action = Sanitizer::cleanString($_GET['action'] ?? $_POST['action'] ?? '');
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $auth = current_auth();

    switch ($action) {
        case 'csrf-token':
            require_method('GET');
            json_ok(['csrf_token' => CSRF::getToken('api')]);
            break;

        case 'me':
            require_method('GET');
            $user = require_auth();
            json_ok(['user' => $user]);
            break;

        case 'register':
            require_method('POST');
            $input = json_input();
            $validator = new Validator($input, [
                'name'     => 'required|max:191',
                'email'    => 'required|email|max:191',
                'password' => 'required|password_strength',
            ]);
            if ($validator->fails()) {
                json_error('Validation failed.', 422, ['errors' => $validator->errors()]);
            }

            $ipKey = RateLimiter::makeKey('api_register_ip', $_SERVER['REMOTE_ADDR'] ?? 'unknown');
            $limiter = new RateLimiter(get_pdo());
            if ($limiter->tooManyAttempts($ipKey, 10, 60)) {
                json_error('Too many registration attempts. Please try again later.', 429);
            }
            $limiter->hit($ipKey, 10, 60);

            $result = $auth->register(
                Sanitizer::cleanString($input['name']),
                Sanitizer::cleanEmail($input['email']),
                (string) $input['password']
            );

            if (!$result['success']) {
                json_error('Registration failed.', 422, ['errors' => $result['errors']]);
            }
            json_ok(['user_id' => $result['user_id']], 201);
            break;

        case 'login':
            require_method('POST');
            $input = json_input();
            $validator = new Validator($input, [
                'email'    => 'required|email',
                'password' => 'required',
            ]);
            if ($validator->fails()) {
                json_error('Validation failed.', 422, ['errors' => $validator->errors()]);
            }

            $remember = Sanitizer::cleanBool($input['remember'] ?? false);
            $result = $auth->attemptLogin(
                Sanitizer::cleanEmail($input['email']),
                (string) $input['password'],
                $remember
            );

            switch ($result['status']) {
                case 'success':
                    log_login_attempt((int) $result['user']['id'], 'success');
                    json_ok(['user' => $result['user'], 'csrf_token' => CSRF::getToken('api')]);
                    break;
                case 'requires_2fa':
                    json_ok(['requires_2fa' => true], 200);
                    break;
                case 'locked':
                    json_error('Too many failed attempts. Please try again later.', 429, ['retry_after' => $result['retry_after']]);
                    break;
                default:
                    $failedUser = $auth->findUserByEmail(Sanitizer::cleanEmail($input['email']));
                    log_login_attempt($failedUser['id'] ?? null, 'failed');
                    json_error($result['errors'][0] ?? 'Invalid credentials.', 401);
            }
            break;

        case 'verify-2fa':
            require_method('POST');
            $input = json_input();
            $totp = Sanitizer::digitsOnly((string) ($input['totp_code'] ?? ''));
            $backup = Sanitizer::cleanString((string) ($input['backup_code'] ?? ''));

            $result = $auth->completeTwoFactorLogin($totp, $backup !== '' ? $backup : null);

            switch ($result['status']) {
                case 'success':
                    log_login_attempt((int) $result['user']['id'], 'success');
                    json_ok(['user' => $result['user'], 'csrf_token' => CSRF::getToken('api')]);
                    break;
                case 'locked':
                    json_error('Too many attempts. Please try again later.', 429, ['retry_after' => $result['retry_after']]);
                    break;
                default:
                    $pendingId = SessionManager::get('auth_pending_2fa_user_id');
                    log_login_attempt($pendingId !== null ? (int) $pendingId : null, 'failed');
                    json_error($result['errors'][0] ?? 'Invalid authentication code.', 401);
            }
            break;

        case 'logout':
            require_method('POST');
            require_auth();
            require_csrf();
            $auth->logout();
            json_ok(['message' => 'Logged out successfully.']);
            break;

        default:
            json_error('Unknown action.', 404);
    }
}
