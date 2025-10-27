<?php

namespace Dracarys\Jwt\Contracts;

use Dracarys\Jwt\Configuration;

interface Builder
{
    public static function fromConfig(Configuration $config): self;

    public function withClaims(array|TokenData $claims): self;

    public function withHeaders(array|TokenData $headers): self;

    public function sign(): Token;
}