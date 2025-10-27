<?php

namespace Dracarys\Jwt\Signer;

use Dracarys\Jwt\Contracts\Signer;
use OpenSSLAsymmetricKey;

abstract class Hmac implements Signer
{
    public function sign(string $data, string|OpenSSLAsymmetricKey $key): string
    {
        return hash_hmac($this->algorithm(), $data, $key, true);
    }

    public function verify($data, $key, $signature): bool
    {
        return hash_equals($this->sign($data, $key), $signature);
    }

    public abstract function algorithm();
}