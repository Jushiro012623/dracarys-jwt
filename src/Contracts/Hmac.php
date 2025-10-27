<?php

namespace Dracarys\Jwt\Contracts;

interface Hmac
{
    public function sign(string $data, string $key): string;

    public function verify(string $data, string $key, string $signature): bool;
}