<?php

namespace Dracarys\Jwt\Signer;

use Dracarys\Jwt\Contracts\Hmac as HmacInterface;

abstract class Hmac implements HmacInterface
{
    public function sign(string $data, string $key): string
    {
        return hash_hmac($this->algorithm(), $data, $key, true);
    }

    public function verify($data, $key, $signature): bool
    {
        return hash_equals($this->sign($data, $key), $signature);
    }

    public abstract function algorithm();
}