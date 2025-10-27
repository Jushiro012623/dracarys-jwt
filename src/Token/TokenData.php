<?php

namespace Dracarys\Jwt\Token;

use Dracarys\Jwt\Contracts\TokenData as TokenDataInterface;

readonly class TokenData implements TokenDataInterface
{
    public function __construct(private array $data = [])
    {}

    public function toArray(): array
    {
        return $this->data;
    }
}
