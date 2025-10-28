<?php

namespace Dracarys\Jwt\Signer;

class Symmetric extends Key
{
    public function __construct(
        private readonly ?string $key)
    {
    }

    public function signingKey(): string
    {
        return $this->key;
    }

    public function verifyingKey(): string
    {
        return $this->key;
    }
}