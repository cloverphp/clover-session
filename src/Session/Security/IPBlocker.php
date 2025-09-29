<?php
namespace Clover\Session\Security;

/**
 * Temporary IP blocking with auto-cleanup
 */
final class IPBlocker {
    private array $blockedIps = [];
    private string $storageFile;
    private int $blockDuration;

    public function __construct(string $storageFile = __DIR__ . '/ip_blocklist.json', int $blockDuration = 1800) {
        $this->storageFile = $storageFile;
        $this->blockDuration = $blockDuration;
        $this->load();
        $this->cleanup();
    }

    private function load(): void {
        if (file_exists($this->storageFile)) {
            $this->blockedIps = json_decode(file_get_contents($this->storageFile), true) ?? [];
        }
    }

    public function block(string $ip): void {
        $this->blockedIps[$ip] = time();
        $this->save();
    }

    public function unblock(string $ip): void {
        unset($this->blockedIps[$ip]);
        $this->save();
    }

    public function isBlocked(string $ip): bool {
        $this->cleanup();
        return isset($this->blockedIps[$ip]);
    }

    private function cleanup(): void {
        $now = time();
        foreach ($this->blockedIps as $ip => $timestamp) {
            if ($now - $timestamp >= $this->blockDuration) {
                unset($this->blockedIps[$ip]);
            }
        }
        $this->save();
    }

    private function save(): void {
        file_put_contents($this->storageFile, json_encode($this->blockedIps, JSON_PRETTY_PRINT));
    }
}
