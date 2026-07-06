<?php
declare(strict_types=1);

/**
 * logout.php
 * Destroys the session, clears the remember-me cookie/token, and
 * redirects to the login page. Requires a CSRF token when triggered
 * via POST to avoid logout CSRF; a plain GET is also supported for
 * simple "Log out" links but is rate-limited by nature of destroying
 * state harmlessly (logging someone out is low-risk, but we still
 * verify same-origin as defense-in-depth).
 */

require_once __DIR__ . '/session.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/csrf.php';
require_once __DIR__ . '/auth.php';

SessionManager::start();
Security::setSecurityHeaders();

function get_pdo(): PDO
{
    static $pdo = null;
    if ($pdo === null) {
        $host = getenv('DB_HOST') ?: '127.0.0.1';
        $name = getenv('DB_NAME') ?: 'app';
        $user = getenv('DB_USER') ?: 'app';
        $pass = getenv('DB_PASS') ?: '';
        $dsn = "mysql:host={$host};dbname={$name};charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]);
    }
    return $pdo;
}

$auth = new Auth(get_pdo());

$isPost = $_SERVER['REQUEST_METHOD'] === 'POST';

if ($isPost) {
    if (!CSRF::verifyRequest('logout')) {
        http_response_code(403);
        echo 'Invalid request.';
        exit;
    }
    $auth->logout();
    header('Location: /login.php');
    exit;
}

// GET fallback: require same-origin referer to reduce logout-CSRF risk,
// then present a tiny confirmation form (avoids state change on bare GET).
if (Security::isSameOrigin() && isset($_GET['confirm']) && $_GET['confirm'] === '1') {
    $auth->logout();
    header('Location: /login.php');
    exit;
}

$csrfToken = CSRF::getToken('logout');
?>
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Log out</title></head>
<body>
<form method="post" action="/logout.php">
    <input type="hidden" name="csrf_token" value="<?= Security::escape($csrfToken) ?>">
    <button type="submit">Confirm log out</button>
</form>
</body>
</html>
