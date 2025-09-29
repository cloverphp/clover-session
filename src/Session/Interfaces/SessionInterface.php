<?php

declare(strict_types=1);

namespace Clover\Session\Interfaces;

/**
 * Interface for session management
 */
interface SessionInterface {
    public function start(): void;

    public function create(string $key, mixed $value): void;

    public function get(string $key, mixed $default = null): mixed;

    public function key(string $key): array;

    public function update(string $key, mixed $value): void;

    public function delete(string $key): void;

    public function destroy(): void;

    public function regenerate(): void;
}
