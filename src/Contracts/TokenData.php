<?php

namespace Dracarys\Jwt\Contracts;

interface TokenData
{
    public function toArray(): array;
}