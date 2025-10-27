<?php

namespace Dracarys\Jwt\Contracts;
use OpenSSLAsymmetricKey;
interface Signer
{
    public function sign(string $data, string|OpenSSLAsymmetricKey  $key): string;

    public function verify(string $data, string|OpenSSLAsymmetricKey  $key, string $signature): bool;
}