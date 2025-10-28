<?php

namespace Dracarys\Jwt\Validation;

use DateTimeInterface;
use Dracarys\Jwt\Contracts\SignerAlgorithm;
use Dracarys\Jwt\Contracts\Token;
use Dracarys\Jwt\Exceptions\TokenValidationException;
use OpenSSLAsymmetricKey;
final readonly class Validator
{
    private function __construct(
        private Token $token,
        private array $errors = []
    )
    {
    }

    public function assert(): void
    {
        if (!empty($this->errors)) {
            throw new TokenValidationException(
                "Token validation failed:\n" . implode("\n", $this->errors)
            );
        }
    }

    public function validate(): bool
    {
        return empty($this->errors);
    }

    public function errors(): array
    {
        return $this->errors;
    }

    public static function fromToken(Token $token): self
    {
        return new self($token);
    }

    public function signedWith(SignerAlgorithm $signer, string|OpenSSLAsymmetricKey  $key): self
    {
        $errors = $this->errors;

        $alg = $this->token->headers()->get('alg');

        if ($alg !== $signer->id()) {
            $errors[] = "SignerAlgorithm mismatch: expected {$signer->id()}, got {$alg}";
        }

        $verified = $signer->verify(
            $this->token->payload(),
            $key,
            $this->token->signature()->hash()
        );

        if (!$verified) {
            $errors[] = 'Signature verification failed.';
        }

        return new self($this->token, $errors);
    }

    public function issuedBy(string ...$issuers): self
    {
        $errors = $this->errors;

        if (!$this->token->hasBeenIssuedBy(...$issuers)) {
            $expected = implode(', ', $issuers);
            $actual = $this->token->claims()->get('iss') ?? 'none';
            $errors[] = "Issuer mismatch: expected one of [{$expected}], got '{$actual}'";
        }
        return new self($this->token, $errors);
    }

    public function permittedFor(string $audience): self
    {
        $errors = $this->errors;
        if (!$this->token->isPermittedFor($audience)) {
            $errors[] = "Audience mismatch: expected '{$audience}', got '{$this->token->claims()->get('aud')}'";
        }
        return new self($this->token, $errors);
    }

    public function identifiedBy(string $jti): self
    {
        $errors = $this->errors;
        if (!$this->token->isIdentifiedBy($jti)) {
            $errors[] = "Subject mismatch: expected '{$jti}', got '{$this->token->claims()->get('jti')}'";
        }
        return new self($this->token, $errors);
    }

    public function relatedTo(string $subject): self
    {
        $errors = $this->errors;
        if (!$this->token->isRelatedTo($subject)) {
            $errors[] = "Subject mismatch: expected '{$subject}', got '{$this->token->claims()->get('sub')}'";
        }
        return new self($this->token, $errors);
    }

    public function notBefore(DateTimeInterface $now): self
    {
        $errors = $this->errors;
        if (!$this->token->hasBeenIssuedBefore($now)) {
            $errors[] = "Token not issued before {$now->format('Y-m-d H:i:s')}";
        }
        return new self($this->token, $errors);
    }

    public function minimumTimeBefore(DateTimeInterface $now): self
    {
        $errors = $this->errors;
        if (!$this->token->isMinimumTimeBefore($now)) {
            $errors[] = "Token not issued before {$now->format('Y-m-d H:i:s')}";
        }
        return new self($this->token, $errors);
    }

    public function notAfter(DateTimeInterface $now): self
    {
        $errors = $this->errors;
        if ($this->token->isExpired($now)) {
            $errors[] = "Token expired at {$now->format('Y-m-d H:i:s')}";
        }
        return new self($this->token, $errors);
    }

    public function custom(callable $callback, ?string $message = null): self
    {
        $errors = $this->errors;

        try {
            $result = $callback($this->token);
            if ($result === false) {
                $errors[] = $message ?? 'Custom validation failed.';
            }
        } catch (\Throwable $e) {
            $errors[] = $message ?? $e->getMessage();
        }

        return new self($this->token, $errors);
    }

}
