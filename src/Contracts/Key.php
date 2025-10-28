<?php

namespace Dracarys\Jwt\Contracts;

use OpenSSLAsymmetricKey;

interface Key
{
    public function signingKey(): string|OpenSSLAsymmetricKey;
    public function verifyingKey(): string|OpenSSLAsymmetricKey;

}