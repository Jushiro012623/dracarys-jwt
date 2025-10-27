<?php

namespace Dracarys\Jwt\Signer;

use OpenSSLAsymmetricKey;

readonly class OpenSSL
{

    public function __construct(
        private ?string $privateKey,
        private ?string $publicKey,
        private string $passphrase = '')
    {

    }

    public function getPrivateKey(): OpenSSLAsymmetricKey
    {
        $privateKey = openssl_pkey_get_private($this->privateKey, $this->passphrase);

        if (!$privateKey) {
            throw new \InvalidArgumentException('Invalid private key.');
        }

        return $privateKey;
    }

    public function getPublicKey(): OpenSSLAsymmetricKey
    {
        $publicKey = openssl_pkey_get_public($this->publicKey);
        if (!$publicKey) {
            throw new \InvalidArgumentException('Invalid public key.');
        }
        return $publicKey;
    }
}