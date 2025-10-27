<?php

namespace Dracarys\Jwt\Helpers;


use Dracarys\Jwt\Contracts\Decoder as DecoderInterface;
use RuntimeException;

class Decoder implements DecoderInterface
{
    public function base64Url(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid base64url string');
        }
        return $decoded;
    }

    public function json(string $data): array
    {
        $json = json_decode($data, true);
        if ($json === null) {
            throw new RuntimeException("Failed to decode: " . json_last_error_msg());
        }
        return $json;
    }
}