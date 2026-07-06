<?php
declare(strict_types=1);

/**
 * api/settings.php
 *
 * Account-level settings (timezone, locale, email visibility, etc).
 * Distinct from api/preferences.php, which covers UI/notification
 * preferences. Stored as a JSON blob on users.settings.
 *
 *   GET /api/settings.php        -> { success, settings }
 *   PUT /api/settings.php        { ...partial settings... } -> { success, settings }
 *
 * Schema addition:
 *   ALTER TABLE users ADD COLUMN settings JSON NULL;
 */

require_once __DIR__ . '/auth.php';

const DEFAULT_SETTINGS = [
    'timezone'            => 'UTC',
    'locale'              => 'en',
    'email_visible'       => false,
    'two_factor_reminder' => true,
];

function validate_timezone(string $tz): bool
{
    return in_array($tz, DateTimeZone::listIdentifiers(), true);
}

function load_settings(PDO $pdo, int $userId): array
{
    $stmt = $pdo->prepare('SELECT settings FROM users WHERE id = :id');
    $stmt->execute(['id' => $userId]);
    $raw = $stmt->fetchColumn();
    $stored = $raw ? (json_decode((string) $raw, true) ?: []) : [];
    return array_merge(DEFAULT_SETTINGS, $stored);
}

$user = require_auth();
$pdo = get_pdo();
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

switch ($method) {
    case 'GET':
        json_ok(['settings' => load_settings($pdo, (int) $user['id'])]);
        break;

    case 'PUT':
    case 'PATCH':
        require_csrf();
        $input = json_input();

        $validator = new Validator($input, [
            'timezone'            => 'max:64',
            'locale'              => 'max:10|alpha_dash',
            'email_visible'       => 'boolean',
            'two_factor_reminder' => 'boolean',
        ]);
        if ($validator->fails()) {
            json_error('Validation failed.', 422, ['errors' => $validator->errors()]);
        }

        if (isset($input['timezone']) && !validate_timezone((string) $input['timezone'])) {
            json_error('Validation failed.', 422, ['errors' => ['timezone' => ['Unknown timezone identifier.']]]);
        }

        $current = load_settings($pdo, (int) $user['id']);
        $updated = $current;

        foreach (['timezone', 'locale'] as $field) {
            if (isset($input[$field])) {
                $updated[$field] = Sanitizer::cleanString((string) $input[$field]);
            }
        }
        foreach (['email_visible', 'two_factor_reminder'] as $field) {
            if (isset($input[$field])) {
                $updated[$field] = Sanitizer::cleanBool($input[$field]);
            }
        }

        $stmt = $pdo->prepare('UPDATE users SET settings = :settings, updated_at = NOW() WHERE id = :id');
        $stmt->execute(['settings' => json_encode($updated), 'id' => $user['id']]);

        json_ok(['settings' => $updated]);
        break;

    default:
        json_error('Method not allowed.', 405);
}
