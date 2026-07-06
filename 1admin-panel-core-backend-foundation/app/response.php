<?php
/**
 * =====================================================================
 * response.php
 * ---------------------------------------------------------------------
 * Standardised JSON output formatter.
 *
 * SCOPE: This is a plain output-formatting utility — it does not
 * define any routes, endpoints, or API surface. It only becomes
 * relevant when a script you write later chooses to call
 * Response::success() / Response::error() to format its own output
 * as JSON (e.g. for an AJAX call from your existing frontend JS).
 * =====================================================================
 */

if (!defined('APP_BOOTSTRAPPED')) {
    http_response_code(403);
    exit('Direct access forbidden.');
}

final class Response
{
    public static function success(mixed $data = null, string $message = 'OK', int $statusCode = 200): never
    {
        self::send([
            'success' => true,
            'message' => $message,
            'data'    => $data,
        ], $statusCode);
    }

    public static function error(string $message = 'Something went wrong', int $statusCode = 400, mixed $errors = null): never
    {
        $payload = [
            'success' => false,
            'message' => $message,
        ];

        if ($errors !== null) {
            $payload['errors'] = $errors;
        }

        self::send($payload, $statusCode);
    }

    public static function send(array $payload, int $statusCode = 200): never
    {
        if (!headers_sent()) {
            http_response_code($statusCode);
            header('Content-Type: application/json; charset=utf-8');
        }

        echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        exit;
    }

    public static function notFound(string $message = 'Not found'): never
    {
        self::error($message, 404);
    }

    public static function validationError(mixed $errors, string $message = 'Validation failed'): never
    {
        self::error($message, 422, $errors);
    }

    public static function serverError(string $message = 'Internal server error'): never
    {
        self::error($message, 500);
    }
}
