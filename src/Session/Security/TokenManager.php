<?php
namespace Clover\Session\Security;

/**
 * Token generator & hasher
 */
final class TokenManager {
    public static function generateToken(int $length = 32): string {
        return bin2hex(random_bytes($length));
    }

    public static function hashToken(string $token): string {
        return hash('sha256', $token);
    }

    public static function verifyToken(string $token, string $hash): bool {
        return hash_equals($hash, self::hashToken($token));
    }
}
