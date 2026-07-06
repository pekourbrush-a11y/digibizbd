<?php
declare(strict_types=1);

/**
 * api/profile.php
 *
 * Manage the authenticated user's own profile.
 *
 *   GET    /api/profile.php            -> { success, profile }
 *   PUT    /api/profile.php            { name?, email?, bio? } -> { success, profile }
 *   DELETE /api/profile.php            { password } -> deactivates the account
 *
 * Schema addition (if not already present):
 *   ALTER TABLE users ADD COLUMN bio TEXT NULL;
 *   ALTER TABLE users ADD COLUMN avatar_url VARCHAR(255) NULL;
 */

require_once __DIR__ . '/auth.php';

$user = require_auth();
$pdo = get_pdo();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

switch ($method) {
    case 'GET':
        $stmt = $pdo->prepare('SELECT id, name, email, bio, avatar_url, created_at, updated_at FROM users WHERE id = :id');
        $stmt->execute(['id' => $user['id']]);
        $profile = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$profile) {
            json_error('Profile not found.', 404);
        }
        json_ok(['profile' => $profile]);
        break;

    case 'PUT':
    case 'PATCH':
        require_csrf();
        $input = json_input();

        $rules = [];
        if (array_key_exists('name', $input)) {
            $rules['name'] = 'required|max:191';
        }
        if (array_key_exists('email', $input)) {
            $rules['email'] = 'required|email|max:191';
        }
        if (array_key_exists('bio', $input)) {
            $rules['bio'] = 'max:1000';
        }

        if (empty($rules)) {
            json_error('No updatable fields were provided.', 422);
        }

        $validator = new Validator($input, $rules);
        if ($validator->fails()) {
            json_error('Validation failed.', 422, ['errors' => $validator->errors()]);
        }

        $fields = [];
        $params = ['id' => $user['id']];

        if (isset($rules['name'])) {
            $fields[] = 'name = :name';
            $params['name'] = Sanitizer::cleanString($input['name']);
        }

        if (isset($rules['email'])) {
            $newEmail = Sanitizer::cleanEmail($input['email']);
            if ($newEmail !== strtolower($user['email'])) {
                $existing = current_auth()->findUserByEmail($newEmail);
                if ($existing !== null && (int) $existing['id'] !== (int) $user['id']) {
                    json_error('That email address is already in use.', 409);
                }
            }
            $fields[] = 'email = :email';
            $params['email'] = $newEmail;
        }

        if (isset($rules['bio'])) {
            $fields[] = 'bio = :bio';
            $params['bio'] = Sanitizer::stripTags((string) $input['bio']);
        }

        $fields[] = 'updated_at = NOW()';

        $stmt = $pdo->prepare('UPDATE users SET ' . implode(', ', $fields) . ' WHERE id = :id');
        $stmt->execute($params);

        $stmt = $pdo->prepare('SELECT id, name, email, bio, avatar_url, created_at, updated_at FROM users WHERE id = :id');
        $stmt->execute(['id' => $user['id']]);
        json_ok(['profile' => $stmt->fetch(PDO::FETCH_ASSOC)]);
        break;

    case 'DELETE':
        require_csrf();
        $input = json_input();
        $password = (string) ($input['password'] ?? '');

        $fullUser = current_auth()->findUserById((int) $user['id']);
        if (!$fullUser || !Password::verify($password, $fullUser['password_hash'])) {
            json_error('Password confirmation is incorrect.', 403);
        }

        $stmt = $pdo->prepare('UPDATE users SET is_active = 0, updated_at = NOW() WHERE id = :id');
        $stmt->execute(['id' => $user['id']]);

        current_auth()->logout();
        json_ok(['message' => 'Account deactivated.']);
        break;

    default:
        json_error('Method not allowed.', 405);
}
