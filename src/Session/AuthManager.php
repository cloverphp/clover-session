<?php
namespace Clover\Session;

use Clover\Session\Security\IPBlocker;
use Clover\Session\Security\RateLimiter;

/**
 * Authentication manager with IP blocking & rate limiting
 */
final class AuthManager {
    private IPBlocker $ipBlocker;
    private RateLimiter $rateLimiter;

    public function __construct() {
        $this->ipBlocker = new IPBlocker();
        $this->rateLimiter = new RateLimiter(5,60);
    }

    public function login(string $userId, string $password, callable $verifyCallback): bool {
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        if ($this->ipBlocker->isBlocked($ip)) return false;
        if (!$this->rateLimiter->allow($ip)) { $this->ipBlocker->block($ip); return false; }

        if ($verifyCallback($userId,$password)) {
            $_SESSION['user_id']=$userId;
            $_SESSION['auth_token']=hash('sha256',$userId.session_id());
            return true;
        }
        return false;
    }

    public function isAuthenticated(): bool {
        return isset($_SESSION['user_id'],$_SESSION['auth_token']) &&
               $_SESSION['auth_token']===hash('sha256',$_SESSION['user_id'].session_id());
    }

    public function logout(): void { unset($_SESSION['user_id'],$_SESSION['auth_token']); session_regenerate_id(true); }
    public function userId(): ?string { return $_SESSION['user_id'] ?? null; }
}
