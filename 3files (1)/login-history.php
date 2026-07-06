<?php
declare(strict_types=1);

/**
 * api/login-history.php
 *
 * Read-only audit log of login attempts. Regular users see only their
 * own history; admins (users.role = 'admin') may pass ?user_id= to
 * inspect another account's history.
 *
 *   GET /api/login-history.php?page=&limit=&status=success|failed
 *   GET /api/login-history.php?user_id=5   (admin only)
 *
 * Schema (also written to by api/auth.php's log_login_attempt() helper):
 *   CREATE TABLE login_history (
 *     id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *     user_id INT UNSIGNED NULL,
 *     ip_address VARCHAR(45) NOT NULL,
 *     user_agent VARCHAR(255) NULL,
 *     status ENUM('success','failed') NOT NULL,
 *     created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     INDEX (user_id, created_at)
 *   ) ENGINE=InnoDB;
 */

require_once __DIR__ . '/auth.php';

require_method('GET');
$user = require_auth();
$pdo = get_pdo();

$targetUserId = (int) $user['id'];
if (isset($_GET['user_id'])) {
    require_role($user, 'admin');
    $targetUserId = Sanitizer::cleanInt($_GET['user_id']);
}

['limit' => $limit, 'offset' => $offset, 'page' => $page] = paginate_params(20, 100);

$status = Sanitizer::cleanString($_GET['status'] ?? '');
$validator = new Validator(['status' => $status], ['status' => 'in:success,failed']);
if ($status !== '' && $validator->fails()) {
    json_error('Invalid status filter.', 422, ['errors' => $validator->errors()]);
}

try {
    $sql = 'SELECT id, ip_address, user_agent, status, created_at FROM login_history WHERE user_id = :uid';
    $params = ['uid' => $targetUserId];

    if ($status !== '') {
        $sql .= ' AND status = :status';
        $params['status'] = $status;
    }
    $sql .= ' ORDER BY created_at DESC LIMIT :limit OFFSET :offset';

    $stmt = $pdo->prepare($sql);
    foreach ($params as $key => $value) {
        $stmt->bindValue($key, $value, PDO::PARAM_STR);
    }
    $stmt->bindValue('limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue('offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $countSql = 'SELECT COUNT(*) FROM login_history WHERE user_id = :uid' . ($status !== '' ? ' AND status = :status' : '');
    $countStmt = $pdo->prepare($countSql);
    foreach ($params as $key => $value) {
        $countStmt->bindValue($key, $value, PDO::PARAM_STR);
    }
    $countStmt->execute();
    $total = (int) $countStmt->fetchColumn();
} catch (PDOException $e) {
    json_ok(['history' => [], 'pagination' => ['page' => $page, 'limit' => $limit, 'total' => 0]]);
}

json_ok([
    'history'    => $rows,
    'pagination' => ['page' => $page, 'limit' => $limit, 'total' => $total],
]);
