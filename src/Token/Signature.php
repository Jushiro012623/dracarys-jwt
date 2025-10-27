<?php

namespace Dracarys\Jwt\Token;

readonly class Signature
{
    public function __construct(private string $hash, private string $encoded)
    {
    }

    public function hash(): string
    {
        return $this->hash;
    }

    public function toString(): string
    {
        return $this->encoded;
    }
}