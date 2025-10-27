<?php

namespace Dracarys\Jwt\Contracts;

interface Decoder
{
    public function base64Url(string $data): string;

    public function json(string $data): array;
}