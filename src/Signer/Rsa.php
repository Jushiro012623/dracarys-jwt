<?php

namespace Dracarys\Jwt\Signer;

use Dracarys\Jwt\Contracts\Signer;
use Dracarys\Jwt\Exceptions\InvalidKeyException;
use OpenSSLAsymmetricKey;
use PHPUnit\Exception;

abstract class Rsa implements Signer
{
    /**
     * Signs the given data using RSA private key
     *
     * @throws InvalidKeyException If the key is invalid
     * @throws \RuntimeException If signing operation fails
     */
    public function sign(string $data, string|OpenSSLAsymmetricKey $key): string
    {
        $privateKey = is_string($key) ? openssl_pkey_get_private($key) : $key;
        if (!$privateKey) {
            throw new InvalidKeyException('Invalid private key: ' . openssl_error_string());
        }

        try {
            $signature = '';
            if (!openssl_sign($data, $signature, $privateKey, $this->algorithm())) {
                throw new \RuntimeException(sprintf(
                    'Failed to sign data using %s: %s',
                    $this->algorithm(),
                    openssl_error_string()
                ));
            }
            return $signature;
        } finally {
            if ($privateKey instanceof \OpenSSLAsymmetricKey) {
                unset($privateKey);
            }
        }

    }

    /**
     * Verifies the signature using RSA public key
     *
     * @throws InvalidKeyException If the key is invalid
     * @throws \RuntimeException If verification operation fails
     */
    public function verify(string $data, string|OpenSSLAsymmetricKey $key, string $signature): bool
    {
        $publicKey = is_string($key) ? openssl_pkey_get_public($key) : $key;
        if (!$publicKey) {
            throw new InvalidKeyException('Invalid public key: ' . openssl_error_string());
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