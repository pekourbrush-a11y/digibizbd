<?php
declare(strict_types=1);

/**
 * api/preferences.php
 *
 * UI/notification preferences, distinct from api/settings.php (which
 * covers account-level settings like timezone/locale). Stored as a
 * JSON blob on users.preferences.
 *
 *   GET /api/preferences.php  -> { success, preferences }
 *   PUT /api/preferences.php  { ...partial preferences... } -> { success, preferences }
 *
 * Schema addition:
 *   ALTER TABLE users ADD COLUMN preferences JSON NULL;
 */

require_once __DIR__ . '/auth.php';

const DEFAULT_PREFERENCES = [
    'theme'               => 'light',
    'email_notifications' => true,
    'push_notifications'  => true,
    'digest_frequency'    => 'weekly',
];

function load_preferences(PDO $pdo, int $userId): array
{
    $stmt = $pdo->prepare('SELECT preferences FROM users WHERE id = :id');
    $stmt->execute(['id' => $userId]);
    $raw = $stmt->fetchColumn();
    $stored = $raw ? (json_decode((string) $raw, true) ?: []) : [];
    return array_merge(DEFAULT_PREFERENCES, $stored);
}

$user = require_auth();
$pdo = get_pdo();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

switch ($method) {
    case 'GET':
        json_ok(['preferences' => load_preferences($pdo, (int) $user['id'])]);
        break;

    case 'PUT':
    case 'PATCH':
        require_csrf();
        $input = json_input();

        $validator = new Validator($input, [
            'theme'               => 'in:light,dark,system',
            'email_notifications' => 'boolean',
            'push_notifications'  => 'boolean',
            'digest_frequency'    => 'in:daily,weekly,monthly,never',
        ]);
        if ($validator->fails()) {
            json_error('Validation failed.', 422, ['errors' => $validator->errors()]);
        }

        $current = load_preferences($pdo, (int) $user['id']);
        $updated = $current;

        foreach (['theme', 'digest_frequency'] as $field) {
            if (isset($input[$field])) {
                $updated[$field] = Sanitizer::cleanString((string) $input[$field]);
            }
        }
        foreach (['email_notifications', 'push_notifications'] as $field) {
            if (isset($input[$field])) {
                $updated[$field] = Sanitizer::cleanBool($input[$field]);
            }
        }

        $stmt = $pdo->prepare('UPDATE users SET preferences = :prefs, updated_at = NOW() WHERE id = :id');
        $stmt->execute(['prefs' => json_encode($updated), 'id' => $user['id']]);

        json_ok(['preferences' => $updated]);
        break;

    default:
        json_error('Method not allowed.', 405);
}
