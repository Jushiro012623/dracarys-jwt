<?php

namespace Dracarys\Jwt\Token;

use DateTimeInterface;
use Dracarys\Jwt\Contracts\Token;
use Dracarys\Jwt\Contracts\UnencryptedToken;

readonly class Jwt implements UnencryptedToken
{

    public function __construct(
        private TokenSegment $headers,
        private TokenSegment $claims,
        private Signature    $signature,
    )
    {
    }

    public function headers(): TokenSegment
    {
        return $this->headers;
    }

    public function claims(): TokenSegment
    {
        return $this->claims;
    }

    public function signature(): Signature
    {
        return $this->signature;
    }

    public function payload(): string
    {
        return "{$this->headers()->toString()}.{$this->claims()->toString()}";
    }

    public function isPermittedFor(string $audience): bool
    {
        $aud = $this->claims->get('aud', []);
        if (!is_array($aud)) {
            $aud = (array) $aud;
        }
        return in_array($audience, $aud, true);
    }

    public function isIdentifiedBy(string $id): bool
    {
        return $this->claims->get('jti') === $id;
    }

    public function isRelatedTo(string $subject): bool
    {
        return $this->claims->get('sub') === $subject;
    }

    public function hasBeenIssuedBy(string ...$issuers): bool
    {
        return in_array($this->claims->get('iss'), $issuers, true);
    }

    public function hasBeenIssuedBefore(DateTimeInterface $now): bool
    {
        return $now >= $this->claims->get('iat');
    }

    public function isMinimumTimeBefore(DateTimeInterface $now): bool
    {
        return $now >= $this->claims->get('nbf');
    }

    public function isExpired(DateTimeInterface $now): bool
    {
        if (!$this->claims->has('exp')) {
            return false;
        }

        return $now >= $this->claims->get('exp');
    }

    public function toString(): string
    {
        $segments = [
            $this->headers->toString(),
            $this->claims->toString(),
            $this->signature->toString()
        ];

        return implode('.', $segments);
    }

}