<?php

namespace Dracarys\Jwt\Helpers;


use Dracarys\Jwt\Contracts\Encoder as EncoderInterface;
use http\Exception\RuntimeException;

class Encoder implements EncoderInterface
{
    public static function base64Url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function json(array $data): string
    {
        $json = json_encode($data, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new RuntimeException("Failed to encode: " . json_last_error_msg());
        }

        return $json;
    }
}