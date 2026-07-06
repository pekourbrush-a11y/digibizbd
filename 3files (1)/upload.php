<?php
declare(strict_types=1);

/**
 * api/upload.php
 *
 * Handles authenticated file uploads (currently: avatar images).
 * Validates real MIME type (not just the client-supplied one), size,
 * and extension; stores under a random filename outside of any
 * user-controlled path to avoid path traversal / overwrite attacks.
 *
 *   POST /api/upload.php   multipart/form-data, field "file" -> { success, url }
 *
 * Requires a writable directory outside the web-executable PHP path,
 * served statically (adjust UPLOAD_DIR / PUBLIC_URL_PREFIX for your setup).
 */

require_once __DIR__ . '/auth.php';

require_method('POST');
$user = require_auth();
require_csrf();

const UPLOAD_MAX_BYTES = 5 * 1024 * 1024; // 5 MB
const UPLOAD_DIR = __DIR__ . '/../../storage/uploads';
const PUBLIC_URL_PREFIX = '/uploads';

const ALLOWED_MIME_EXTENSIONS = [
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/webp' => 'webp',
];

if (!isset($_FILES['file']) || !is_array($_FILES['file'])) {
    json_error('No file was uploaded.', 422);
}

$file = $_FILES['file'];

$uploadErrorMessages = [
    UPLOAD_ERR_INI_SIZE   => 'The file exceeds the maximum allowed size.',
    UPLOAD_ERR_FORM_SIZE  => 'The file exceeds the maximum allowed size.',
    UPLOAD_ERR_PARTIAL    => 'The file was only partially uploaded.',
    UPLOAD_ERR_NO_FILE    => 'No file was uploaded.',
    UPLOAD_ERR_NO_TMP_DIR => 'Server upload configuration error.',
    UPLOAD_ERR_CANT_WRITE => 'Server upload configuration error.',
    UPLOAD_ERR_EXTENSION  => 'The upload was blocked by a server extension.',
];

if ($file['error'] !== UPLOAD_ERR_OK) {
    json_error($uploadErrorMessages[$file['error']] ?? 'Upload failed.', 422);
}

if (!is_uploaded_file($file['tmp_name'])) {
    json_error('Invalid upload.', 422);
}

if ($file['size'] <= 0 || $file['size'] > UPLOAD_MAX_BYTES) {
    json_error('File size must be between 1 byte and 5 MB.', 422);
}

$finfo = new finfo(FILEINFO_MIME_TYPE);
$realMimeType = $finfo->file($file['tmp_name']) ?: '';

if (!isset(ALLOWED_MIME_EXTENSIONS[$realMimeType])) {
    json_error('Only JPEG, PNG, and WEBP images are allowed.', 422);
}

// Double-check it actually decodes as an image (defense against polyglot files).
$imageInfo = @getimagesize($file['tmp_name']);
if ($imageInfo === false) {
    json_error('The uploaded file is not a valid image.', 422);
}

if (!is_dir(UPLOAD_DIR) && !mkdir(UPLOAD_DIR, 0750, true) && !is_dir(UPLOAD_DIR)) {
    json_error('Server storage is not available.', 500);
}

$extension = ALLOWED_MIME_EXTENSIONS[$realMimeType];
$filename = bin2hex(random_bytes(16)) . '.' . $extension;
$destination = UPLOAD_DIR . '/' . $filename;

if (!move_uploaded_file($file['tmp_name'], $destination)) {
    json_error('Failed to store the uploaded file.', 500);
}
chmod($destination, 0640);

$publicUrl = PUBLIC_URL_PREFIX . '/' . $filename;

// Persist as the user's avatar. Requires: ALTER TABLE users ADD COLUMN avatar_url VARCHAR(255) NULL;
$pdo = get_pdo();
$stmt = $pdo->prepare('UPDATE users SET avatar_url = :url, updated_at = NOW() WHERE id = :id');
$stmt->execute(['url' => $publicUrl, 'id' => $user['id']]);

json_ok(['url' => $publicUrl], 201);
