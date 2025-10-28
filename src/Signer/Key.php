<?php

namespace Dracarys\Jwt\Signer;

use OpenSSLAsymmetricKey;
use Dracarys\Jwt\Contracts\Key as KeyInterface;
abstract class Key implements KeyInterface
{
    public abstract function signingKey(): string|OpenSSLAsymmetricKey;
    public abstract function verifyingKey(): string|OpenSSLAsymmetricKey;


}