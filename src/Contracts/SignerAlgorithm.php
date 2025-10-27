<?php

namespace Dracarys\Jwt\Contracts;

interface SignerAlgorithm
{
    public function algorithm(): string|int;

    public function id(): string;

}