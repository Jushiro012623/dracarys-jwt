<?php

namespace Dracarys\Jwt;

use Dracarys\Jwt\Contracts\Decoder as DecoderInterface;
use Dracarys\Jwt\Contracts\Encoder as EncoderInterface;
use Dracarys\Jwt\Contracts\Token;
use Dracarys\Jwt\Contracts\TokenData;
use Dracarys\Jwt\Contracts\Signer;
use Dracarys\Jwt\Helpers\Decoder;
use Dracarys\Jwt\Helpers\Encoder;
use Dracarys\Jwt\Token\Builder;
use Dracarys\Jwt\Token\Jwt;
use Dracarys\Jwt\Token\Parser;
use Dracarys\Jwt\Validation\Validator;

readonly class Configuration
{
    private function __construct(
        private Signer           $signer,
        private string           $signingKey,
        private string           $verificationKey,
        private DecoderInterface $decoder = new Decoder(),
        private EncoderInterface $encoder = new Encoder()
    )
    {
    }

    public static function symmetric(Signer $signer, string $key): Configuration
    {
        return new self($signer, $key, $key);
    }

    public static function asymmetric(Signer $signer, string $publicKey, string $privateKey): Configuration
    {
        return new self($signer, $publicKey, $privateKey);
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

    public function signer(): Signer
    {
        return $this->signer;
    }

    public function signingKey(): string
    {
        return $this->signingKey;
    }

    public function verificationKey(): string
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

    public function validator(Token $token): Validator
    {
        return Validator::fromToken($token);
    }

}