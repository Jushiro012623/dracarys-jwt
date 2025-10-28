<?php

namespace Dracarys\Jwt;

use Dracarys\Jwt\Contracts\Decoder as DecoderInterface;
use Dracarys\Jwt\Contracts\Encoder as EncoderInterface;
use Dracarys\Jwt\Contracts\Token;
use Dracarys\Jwt\Contracts\TokenData;
use Dracarys\Jwt\Contracts\SignerAlgorithm;
use Dracarys\Jwt\Contracts\UnencryptedToken;
use Dracarys\Jwt\Helpers\Decoder;
use Dracarys\Jwt\Helpers\Encoder;
use Dracarys\Jwt\Signer\Key;
use Dracarys\Jwt\Signer\OpenSSL;
use Dracarys\Jwt\Token\Builder;
use Dracarys\Jwt\Token\Parser;
use Dracarys\Jwt\Validation\Validator;
use OpenSSLAsymmetricKey;

readonly class Configuration
{
    private function __construct(
        private SignerAlgorithm             $signer,
        private string|OpenSSLAsymmetricKey $signingKey,
        private string|OpenSSLAsymmetricKey $verificationKey,
        private DecoderInterface            $decoder = new Decoder(),
        private EncoderInterface            $encoder = new Encoder()
    )
    {
    }

    public static function symmetric(SignerAlgorithm $signer, Key $key): Configuration
    {
        return new self($signer, $key->signingKey(), $key->verifyingKey());
    }

    public static function asymmetric(SignerAlgorithm $signer, Key $key): Configuration
    {
        return new self($signer, $key->signingKey(), $key->verifyingKey());
    }

    public function setDecoder(DecoderInterface $decoder): Configuration
    {
        return new self($this->signer(), $this->signingKey(), $this->verificationKey(), $decoder);
    }

    public function setEncoder(EncoderInterface $encoder): Configuration
    {
        return new self($this->signer(), $this->signingKey(), $this->verificationKey(), encoder: $encoder);
    }

    public function decoder(): DecoderInterface
    {
        return $this->decoder;
    }

    public function encoder(): EncoderInterface
    {
        return $this->encoder;
    }

    public function signer(): SignerAlgorithm
    {
        return $this->signer;
    }

    public function signingKey(): string|OpenSSLAsymmetricKey
    {
        return $this->signingKey;
    }

    public function verificationKey(): string|OpenSSLAsymmetricKey
    {
        return $this->verificationKey;
    }

    public function createToken(array|TokenData $payload = [], array|TokenData $headers = []): Token
    {
        return Builder::fromConfig($this)->withClaims($payload)->withHeaders($headers)->sign();
    }

    public function parser(): Parser
    {
        return new Parser($this->decoder);
    }

    public function validator(UnencryptedToken $token): Validator
    {
        return Validator::fromToken($token);
    }

}