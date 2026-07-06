<?php
declare(strict_types=1);

/**
 * api/notifications.php
 *
 * User notifications.
 *
 *   GET    /api/notifications.php?unread=1&page=&limit=  -> paginated list
 *   POST   /api/notifications.php?action=mark-read  { id }
 *   POST   /api/notifications.php?action=mark-all-read
 *   DELETE /api/notifications.php?id=5
 *
 * Schema:
 *   CREATE TABLE notifications (
 *     id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
 *     user_id INT UNSIGNED NOT NULL,
 *     type VARCHAR(50) NOT NULL,
 *     title VARCHAR(191) NOT NULL,
 *     message TEXT NULL,
 *     read_at DATETIME NULL,
 *     created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     INDEX (user_id, read_at)
 *   ) ENGINE=InnoDB;
 */

require_once __DIR__ . '/auth.php';

$user = require_auth();
$pdo = get_pdo();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$action = Sanitizer::cleanString($_GET['action'] ?? $_POST['action'] ?? '');

if ($method === 'GET') {
    ['limit' => $limit, 'offset' => $offset, 'page' => $page] = paginate_params(20, 100);
    $unreadOnly = Sanitizer::cleanBool($_GET['unread'] ?? false);

    $sql = 'SELECT id, type, title, message, read_at, created_at FROM notifications WHERE user_id = :uid';
    if ($unreadOnly) {
        $sql .= ' AND read_at IS NULL';
    }
    $sql .= ' ORDER BY created_at DESC LIMIT :limit OFFSET :offset';

    $stmt = $pdo->prepare($sql);
    $stmt->bindValue('uid', $user['id'], PDO::PARAM_INT);
    $stmt->bindValue('limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue('offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $countStmt = $pdo->prepare(
        'SELECT COUNT(*) FROM notifications WHERE user_id = :uid' . ($unreadOnly ? ' AND read_at IS NULL' : '')
    );
    $countStmt->bindValue('uid', $user['id'], PDO::PARAM_INT);
    $countStmt->execute();
    $total = (int) $countStmt->fetchColumn();

    json_ok([
        'notifications' => $rows,
        'pagination'    => ['page' => $page, 'limit' => $limit, 'total' => $total],
    ]);
}

if ($method === 'POST' && $action === 'mark-read') {
    require_csrf();
    $input = json_input();
    $id = Sanitizer::cleanInt($input['id'] ?? 0);
    if ($id <= 0) {
        json_error('A valid notification id is required.', 422);
    }

    $stmt = $pdo->prepare(
        'UPDATE notifications SET read_at = NOW() WHERE id = :id AND user_id = :uid AND read_at IS NULL'
    );
    $stmt->execute(['id' => $id, 'uid' => $user['id']]);

    json_ok(['message' => 'Notification marked as read.']);
}

if ($method === 'POST' && $action === 'mark-all-read') {
    require_csrf();
    $stmt = $pdo->prepare('UPDATE notifications SET read_at = NOW() WHERE user_id = :uid AND read_at IS NULL');
    $stmt->execute(['uid' => $user['id']]);
    json_ok(['message' => 'All notifications marked as read.']);
}

if ($method === 'DELETE') {
    require_csrf();
    $id = Sanitizer::cleanInt($_GET['id'] ?? 0);
    if ($id <= 0) {
        json_error('A valid notification id is required.', 422);
    }

    $stmt = $pdo->prepare('DELETE FROM notifications WHERE id = :id AND user_id = :uid');
    $stmt->execute(['id' => $id, 'uid' => $user['id']]);

    if ($stmt->rowCount() === 0) {
        json_error('Notification not found.', 404);
    }
    json_ok(['message' => 'Notification deleted.']);
}

json_error('Unknown action or method.', 404);
