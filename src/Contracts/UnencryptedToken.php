<?php

namespace Dracarys\Jwt\Contracts;

use Dracarys\Jwt\Token\Signature;
use Dracarys\Jwt\Token\TokenSegment;

interface UnencryptedToken extends Token
{
    public function claims(): TokenSegment;

    public function signature(): Signature;

    public function payload(): string;
}