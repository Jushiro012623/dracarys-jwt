<?php

namespace Dracarys\Jwt\Signer;

use OpenSSLAsymmetricKey;

readonly class Key
{
    private function __construct(private string|OpenSSLAsymmetricKey $signingKey = '', private string|OpenSSLAsymmetricKey $verifyingKey = '')
    {
    }

    public static function secret($key): self
    {
        return new self($key, $key);
    }

    public static function openSSL(OpenSSL $openSSL): self
    {
        return new self($openSSL->getPrivateKey(), $openSSL->getPublicKey());
    }

    public function signingKey(): string|OpenSSLAsymmetricKey
    {
        return $this->signingKey;
    }

    public function verifyingKey(): string|OpenSSLAsymmetricKey
    {
        return $this->verifyingKey;
    }
}