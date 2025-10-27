<?php

namespace Dracarys\Jwt\Contracts;

interface Signer
{
    public function algorithm(): string;

    public function id(): string;

}