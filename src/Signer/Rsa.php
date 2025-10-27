<?php

namespace Dracarys\Jwt\Signer;

use Dracarys\Jwt\Contracts\Signer;
use OpenSSLAsymmetricKey;

abstract class Rsa implements Signer
{
    /**
     * Signs the given data using RSA private key
     *
     * @throws \InvalidArgumentException If the key is invalid
     * @throws \RuntimeException If signing operation fails
     */
    public function sign(string $data, string|OpenSSLAsymmetricKey $key): string
    {
        $privateKey = is_string($key) ? openssl_pkey_get_private($key) : $key;
        if (!$privateKey) {
            throw new \InvalidArgumentException('Invalid private key: ' . openssl_error_string());
        }

        try {
            $signature = '';
            if (!openssl_sign($data, $signature, $privateKey, $this->algorithm())) {
                throw new \RuntimeException('Failed to sign data: ' . openssl_error_string());
            }
            return $signature;
        } finally {
            if ($privateKey instanceof \OpenSSLAsymmetricKey) {
                unset($publicKey);
            }
        }

    }

    /**
     * Verifies the signature using RSA public key
     *
     * @throws \InvalidArgumentException If the key is invalid
     * @throws \RuntimeException If verification operation fails
     */
    public function verify(string $data, string|OpenSSLAsymmetricKey $key, string $signature): bool
    {
        $publicKey = is_string($key) ? openssl_pkey_get_public($key) : $key;
        if (!$publicKey) {
            throw new \InvalidArgumentException('Invalid public key: ' . openssl_error_string());
        }

        try {
            $result = openssl_verify($data, $signature, $publicKey, $this->algorithm());
            if ($result === -1) {
                throw new \RuntimeException('Signature verification failed: ' . openssl_error_string());
            }
            return $result === 1;
        } finally {
            if ($publicKey instanceof \OpenSSLAsymmetricKey) {
                unset($publicKey);
            }
        }
    }

    public abstract function algorithm();
}