<?php
declare(strict_types=1);

/**
 * api/users.php
 *
 * Admin-only user management. Requires the authenticated user to have
 * users.role = 'admin'.
 *
 *   GET    /api/users.php                 -> paginated list, ?search=&page=&limit=
 *   GET    /api/users.php?id=5            -> single user
 *   PUT    /api/users.php?id=5            { name?, email?, role?, is_active? }
 *   DELETE /api/users.php?id=5            -> deactivates (soft delete)
 *
 * Schema addition:
 *   ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user';
 */

require_once __DIR__ . '/auth.php';

$currentUser = require_auth();
require_role($currentUser, 'admin');

$pdo = get_pdo();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$id = isset($_GET['id']) ? Sanitizer::cleanInt($_GET['id']) : null;

$userPublicColumns = 'id, name, email, role, is_active, created_at, updated_at';

switch ($method) {
    case 'GET':
        if ($id !== null) {
            $stmt = $pdo->prepare("SELECT {$userPublicColumns} FROM users WHERE id = :id");
            $stmt->execute(['id' => $id]);
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) {
                json_error('User not found.', 404);
            }
            json_ok(['user' => $row]);
        }

        ['limit' => $limit, 'offset' => $offset, 'page' => $page] = paginate_params(20, 100);
        $search = Sanitizer::cleanString($_GET['search'] ?? '');

        if ($search !== '') {
            $stmt = $pdo->prepare(
                "SELECT {$userPublicColumns} FROM users
                 WHERE name LIKE :search OR email LIKE :search
                 ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
            );
            $stmt->bindValue('search', '%' . $search . '%', PDO::PARAM_STR);
        } else {
            $stmt = $pdo->prepare(
                "SELECT {$userPublicColumns} FROM users ORDER BY created_at DESC LIMIT :limit OFFSET :offset"
            );
        }
        $stmt->bindValue('limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue('offset', $offset, PDO::PARAM_INT);
        $stmt->execute();
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $countStmt = $search !== ''
            ? $pdo->prepare('SELECT COUNT(*) FROM users WHERE name LIKE :search OR email LIKE :search')
            : $pdo->prepare('SELECT COUNT(*) FROM users');
        if ($search !== '') {
            $countStmt->bindValue('search', '%' . $search . '%', PDO::PARAM_STR);
        }
        $countStmt->execute();
        $total = (int) $countStmt->fetchColumn();

        json_ok([
            'users'      => $rows,
            'pagination' => ['page' => $page, 'limit' => $limit, 'total' => $total],
        ]);
        break;

    case 'PUT':
    case 'PATCH':
        if ($id === null) {
            json_error('A user id is required.', 422);
        }
        require_csrf();
        $input = json_input();

        $rules = [];
        if (array_key_exists('name', $input)) $rules['name'] = 'required|max:191';
        if (array_key_exists('email', $input)) $rules['email'] = 'required|email|max:191';
        if (array_key_exists('role', $input)) $rules['role'] = 'required|in:user,admin';
        if (array_key_exists('is_active', $input)) $rules['is_active'] = 'boolean';

        if (empty($rules)) {
            json_error('No updatable fields were provided.', 422);
        }

        $validator = new Validator($input, $rules);
        if ($validator->fails()) {
            json_error('Validation failed.', 422, ['errors' => $validator->errors()]);
        }

        $fields = [];
        $params = ['id' => $id];

        if (isset($rules['name'])) {
            $fields[] = 'name = :name';
            $params['name'] = Sanitizer::cleanString($input['name']);
        }
        if (isset($rules['email'])) {
            $fields[] = 'email = :email';
            $params['email'] = Sanitizer::cleanEmail($input['email']);
        }
        if (isset($rules['role'])) {
            $fields[] = 'role = :role';
            $params['role'] = Sanitizer::cleanString($input['role']);
        }
        if (isset($rules['is_active'])) {
            $fields[] = 'is_active = :is_active';
            $params['is_active'] = Sanitizer::cleanBool($input['is_active']) ? 1 : 0;
        }
        $fields[] = 'updated_at = NOW()';

        $stmt = $pdo->prepare('UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = :id');
        $stmt->execute($params);

        $stmt = $pdo->prepare("SELECT {$userPublicColumns} FROM users WHERE id = :id");
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if (!$row) {
            json_error('User not found.', 404);
        }
        json_ok(['user' => $row]);
        break;

    case 'DELETE':
        if ($id === null) {
            json_error('A user id is required.', 422);
        }
        require_csrf();

        if ($id === (int) $currentUser['id']) {
            json_error('You cannot deactivate your own account from this endpoint.', 422);
        }

        $stmt = $pdo->prepare('UPDATE users SET is_active = 0, updated_at = NOW() WHERE id = :id');
        $stmt->execute(['id' => $id]);

        if ($stmt->rowCount() === 0) {
            json_error('User not found.', 404);
        }

        $rememberMe = new RememberMe($pdo);
        $rememberMe->forgetAllForUser($id);

        json_ok(['message' => 'User deactivated.']);
        break;

    default:
        json_error('Method not allowed.', 405);
}
