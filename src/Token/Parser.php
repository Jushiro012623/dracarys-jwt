<?php

namespace Dracarys\Jwt\Token;

use Dracarys\Jwt\Contracts\Decoder as DecoderInterface;
use Dracarys\Jwt\Contracts\Token;
use Dracarys\Jwt\Exceptions\InvalidTokenException;
use Dracarys\Jwt\Helpers\Decoder;

readonly class Parser
{
    public function __construct(private DecoderInterface $decoder = new Decoder())
    {
    }

    public function parse(string $jwt): Token
    {
        [$tokenHeader, $tokenClaims, $tokenSignature] = $this->jwtParts($jwt);
        $header = $this->decodePart('header', $tokenHeader);
        $payload = $this->decodePart('claims', $tokenClaims);

        return new Jwt(
            new TokenSegment ($header, $tokenHeader),
            new TokenSegment ($payload, $tokenClaims),
            new Signature($this->decoder->base64Url($tokenSignature), $tokenSignature)
        );
    }

    private function jwtParts(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new InvalidTokenException('Token structure invalid');
        }
        return $parts;
    }

    private function decodePart(string $type, string $data): array
    {
        if (trim($data) === '') {
            throw new InvalidTokenException("Token is missing the {$type} part");
        }

        $decoded = $this->decoder->json(
            $this->decoder->base64Url($data)
        );

        if (!is_array($decoded)) {
            throw new InvalidTokenException("Token {$type} part is not valid JSON");
        }

        return $decoded;
    }

}