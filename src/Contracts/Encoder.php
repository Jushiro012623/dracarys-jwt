<?php

namespace Dracarys\Jwt\Contracts;

interface Encoder
{
    public static function base64Url(string $data): string;

    public static function json(array $data): string;
}