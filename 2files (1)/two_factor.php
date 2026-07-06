<?php
declare(strict_types=1);

/**
 * TwoFactorAuth
 * RFC 6238 TOTP implementation compatible with Google Authenticator,
 * Authy, Microsoft Authenticator, etc. Base32 secret encode/decode,
 * otpauth:// URI generation for QR codes, and code verification with
 * a configurable time-step window to tolerate clock drift.
 */
final class TwoFactorAuth
{
    private const SECRET_BYTE_LENGTH = 20; // 160-bit secret (standard for TOTP)
    private const CODE_DIGITS = 6;
    private const TIME_STEP = 30; // seconds
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /** Generate a new random Base32-encoded secret. */
    public static function generateSecret(int $byteLength = self::SECRET_BYTE_LENGTH): string
    {
        return self::base32Encode(random_bytes($byteLength));
    }

    /**
     * Build an otpauth:// URI for QR-code generation, readable by
     * Google Authenticator and compatible apps.
     */
    public static function getQRCodeUrl(string $issuer, string $accountName, string $secret): string
    {
        $label = rawurlencode($issuer) . ':' . rawurlencode($accountName);
        $query = http_build_query([
            'secret'    => $secret,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => self::CODE_DIGITS,
            'period'    => self::TIME_STEP,
        ], '', '&', PHP_QUERY_RFC3986);

        return "otpauth://totp/{$label}?{$query}";
    }

    /** Generate a URL to render the QR code image via an external service (optional convenience). */
    public static function getQRCodeImageUrl(string $issuer, string $accountName, string $secret, int $size = 200): string
    {
        $otpauth = self::getQRCodeUrl($issuer, $accountName, $secret);
        return "https://api.qrserver.com/v1/create-qr-code/?size={$size}x{$size}&data=" . rawurlencode($otpauth);
    }

    /** Compute the TOTP code for a given secret at a given Unix timestamp. */
    public static function getCode(string $secret, ?int $timestamp = null): string
    {
        $timestamp = $timestamp ?? time();
        $counter = (int) floor($timestamp / self::TIME_STEP);
        return self::hotp($secret, $counter);
    }

    /**
     * Verify a user-submitted code, allowing +/- $window time-steps of drift
     * (default 1 step = ~30s each direction => 90s total tolerance).
     */
    public static function verifyCode(string $secret, string $code, int $window = 1): bool
    {
        $code = preg_replace('/\D/', '', $code) ?? '';
        if (strlen($code) !== self::CODE_DIGITS) {
            return false;
        }

        $timestamp = time();
        $counter = (int) floor($timestamp / self::TIME_STEP);

        for ($i = -$window; $i <= $window; $i++) {
            $expected = self::hotp($secret, $counter + $i);
            if (hash_equals($expected, $code)) {
                return true;
            }
        }
        return false;
    }

    /** HOTP per RFC 4226, used as the building block for TOTP. */
    private static function hotp(string $base32Secret, int $counter): string
    {
        $key = self::base32Decode($base32Secret);
        $counterBytes = pack('N*', 0, $counter); // 8-byte big-endian counter

        $hash = hash_hmac('sha1', $counterBytes, $key, true);
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;

        $binary = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);

        $otp = $binary % (10 ** self::CODE_DIGITS);
        return str_pad((string) $otp, self::CODE_DIGITS, '0', STR_PAD_LEFT);
    }

    /** Generate one-time backup/recovery codes (store hashed, show once). */
    public static function generateBackupCodes(int $count = 8): array
    {
        $codes = [];
        for ($i = 0; $i < $count; $i++) {
            $codes[] = strtoupper(bin2hex(random_bytes(5))); // 10 hex chars, human-typeable
        }
        return $codes;
    }

    public static function hashBackupCode(string $code): string
    {
        return hash('sha256', strtoupper(trim($code)));
    }

    // ---- Base32 -----------------------------------------------------------

    public static function base32Encode(string $data): string
    {
        if ($data === '') {
            return '';
        }
        $bits = '';
        foreach (str_split($data) as $char) {
            $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
        }

        $output = '';
        foreach (str_split($bits, 5) as $chunk) {
            if (strlen($chunk) < 5) {
                $chunk = str_pad($chunk, 5, '0', STR_PAD_RIGHT);
            }
            $output .= self::BASE32_ALPHABET[bindec($chunk)];
        }

        return $output;
    }

    public static function base32Decode(string $base32): string
    {
        $base32 = strtoupper(preg_replace('/[^A-Z2-7]/i', '', $base32) ?? '');
        $bits = '';
        foreach (str_split($base32) as $char) {
            $pos = strpos(self::BASE32_ALPHABET, $char);
            if ($pos === false) {
                continue;
            }
            $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
        }

        $bytes = '';
        foreach (str_split($bits, 8) as $byte) {
            if (strlen($byte) === 8) {
                $bytes .= chr(bindec($byte));
            }
        }

        return $bytes;
    }
}
