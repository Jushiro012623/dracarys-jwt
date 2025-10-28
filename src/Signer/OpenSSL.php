<?php

namespace Dracarys\Jwt\Signer;

use OpenSSLAsymmetricKey;

class OpenSSL extends Key
{
    private ?OpenSSLAsymmetricKey $privateKeyObj = null;
    private ?OpenSSLAsymmetricKey $publicKeyObj = null;

    public function __construct(
        private readonly ?string $privateKey,
        private readonly ?string $publicKey,
        private readonly string  $passphrase = '')
    {
    }

    public function signingKey(): OpenSSLAsymmetricKey
    {
        if ($this->privateKeyObj) return $this->privateKeyObj;

        $key = openssl_pkey_get_private($this->privateKey, $this->passphrase);
        if (!$key) {
            throw new \InvalidArgumentException('Invalid private key.');
        }
        return $this->privateKeyObj = $key;
    }

    public function verifyingKey(): OpenSSLAsymmetricKey
    {
        if ($this->publicKeyObj) return $this->publicKeyObj;

        $key = openssl_pkey_get_public($this->publicKey);
        if (!$key) {
            throw new \InvalidArgumentException('Invalid public key.');
        }
        return $this->publicKeyObj = $key;
    }

}