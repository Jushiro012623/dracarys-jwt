<?php

namespace Dracarys\Jwt\Token;

readonly class TokenSegment
{
    public function __construct(private array $data, private string $encoded)
    {
    }

    public function get(string $name, mixed $default = null): mixed
    {
        return $this->data[$name] ?? $default;
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->data);
    }

    public function all(): array
    {
        return $this->data;
    }

    public function toString(): string
    {
        return $this->encoded;
    }
}