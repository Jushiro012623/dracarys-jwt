<?php

namespace Dracarys\Jwt\Token;

use Dracarys\Jwt\Configuration;
use Dracarys\Jwt\Contracts\Token;
use Dracarys\Jwt\Contracts\TokenData;
use Dracarys\Jwt\Contracts\Builder as BuilderInterface;

readonly final class Builder implements BuilderInterface
{
    public function __construct(
        private Configuration $config,
        private array         $payload = [],
        private array         $headers = [],
    )
    {}

    public static function fromConfig(Configuration $config): self
    {
        return new self($config);
    }

    public function withClaims(array|TokenData $claims): self
    {
        $payload = $claims instanceof TokenData ? $claims->toArray() : $claims;
        $newClaims = array_merge($this->payload, $payload);
        return new self($this->config, $newClaims, $this->headers);
    }

    public function withHeaders(array|TokenData $headers): self
    {
        $headers = $headers instanceof TokenData ? $headers->toArray() : $headers;
        $newHeaders = array_merge($this->headers, $headers);
        return new self($this->config, $this->payload, $newHeaders);
    }

    public function sign(): Token
    {
        $headers = $this->prepareHeaders($this->config->signer()->id());
        $payload = $this->payload;

        $encoder = $this->config->encoder();

        $headersEncoded = $encoder->base64Url($encoder->json($headers));
        $payloadEncoded = $encoder->base64Url($encoder->json($payload));

        $signingInput = implode('.', [$headersEncoded, $payloadEncoded]);
        $signature = $this->config->signer()->sign($signingInput, $this->config->signingKey());
        $signatureEncoded = $encoder->base64Url($signature);

        return new Jwt(
            new TokenSegment($headers, $headersEncoded),
            new TokenSegment($payload, $payloadEncoded),
            new Signature($signature, $signatureEncoded)
        );
    }

    private function prepareHeaders(string $algorithm): array
    {
        $headers = $this->headers;

        if (!array_key_exists('typ', $headers)) {
            $headers['typ'] = 'JWT';
        }

        $headers['alg'] = $algorithm;

        return $headers;
    }
}
