<?php

declare(strict_types=1);

namespace App\Service\Security;

use App\Entity\User;

/**
 * TotpService — Handles TOTP (Time-based One-Time Password) generation and verification.
 * 
 * Implements RFC 6238 using native PHP functions.
 * Does not depend on external libraries for maximum compatibility.
 */
class TotpService
{
    private const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    /**
     * Generate a random 16-character Base32 secret key.
     */
    public function generateSecret(): string
    {
        $secret = '';
        $bytes = random_bytes(10); // 80 bits of entropy
        
        // Convert bytes to Base32
        $n = 0;
        $j = 0;
        foreach (str_split($bytes) as $byte) {
            $n = ($n << 8) | ord($byte);
            $j += 8;
            while ($j >= 5) {
                $j -= 5;
                $secret .= self::BASE32_ALPHABET[($n >> $j) & 31];
            }
        }
        
        return $secret;
    }

    /**
     * Generate the otpauth:// URI for QR code generation.
     */
    public function getQrUri(User $user, string $secret, string $issuer = 'SymphonyAuth'): string
    {
        $label = $issuer . ':' . $user->getEmail();
        return sprintf(
            'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
            rawurlencode($label),
            $secret,
            rawurlencode($issuer)
        );
    }

    /**
     * Verify a 6-digit TOTP code against a secret key.
     * 
     * @param string $secret The Base32 secret key
     * @param string $code   The 6-digit code to verify
     * @param int $discrepancy Number of 30-second windows to check (default 1 = ±30s)
     */
    public function verifyCode(string $secret, string $code, int $discrepancy = 1): bool
    {
        if (strlen($code) !== 6 || !is_numeric($code)) {
            return false;
        }

        $currentTimeSlice = (int) floor(time() / 30);

        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = $this->calculateCode($secret, $currentTimeSlice + $i);
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Calculate the 6-digit code for a specific time slice.
     */
    private function calculateCode(string $secret, int $timeSlice): string
    {
        $secretKey = $this->base32Decode($secret);

        // Pack time slice into 8-byte binary string (big-endian)
        $timeBytes = pack('N*', 0) . pack('N*', $timeSlice);

        // HMAC-SHA1
        $hash = hash_hmac('sha1', $timeBytes, $secretKey, true);

        // Dynamic truncation
        $offset = ord($hash[19]) & 0xf;
        $truncatedHash = (
            (ord($hash[$offset]) & 0x7f) << 24 |
            (ord($hash[$offset + 1]) & 0xff) << 16 |
            (ord($hash[$offset + 2]) & 0xff) << 8 |
            (ord($hash[$offset + 3]) & 0xff)
        );

        $code = $truncatedHash % 1000000;
        return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
    }

    /**
     * Decode a Base32 string into a binary string.
     */
    private function base32Decode(string $base32): string
    {
        $base32 = strtoupper($base32);
        $alphabet = self::BASE32_ALPHABET;
        $decoded = '';
        $n = 0;
        $j = 0;

        foreach (str_split($base32) as $char) {
            $v = strpos($alphabet, $char);
            if ($v === false) {
                continue;
            }
            $n = ($n << 5) | $v;
            $j += 5;
            if ($j >= 8) {
                $j -= 8;
                $decoded .= chr(($n >> $j) & 255);
            }
        }

        return $decoded;
    }
}
