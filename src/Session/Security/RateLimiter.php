<?php
namespace Clover\Session\Security;

/**
 * Simple per-IP rate limiter
 */
final class RateLimiter {
    private array $requests = [];
    private int $limit;
    private int $window;

    public function __construct(int $limit = 5, int $window = 60) {
        $this->limit = $limit;
        $this->window = $window;
    }

    public function allow(string $ip): bool {
        $now = time();
        $this->requests[$ip] = array_filter($this->requests[$ip] ?? [], fn($t) => $t > $now - $this->window);
        if (count($this->requests[$ip]) >= $this->limit) return false;
        $this->requests[$ip][] = $now;
        return true;
    }
}
