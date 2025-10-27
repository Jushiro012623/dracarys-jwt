<?php

namespace Dracarys\Jwt\Signer\Hmac;

use Dracarys\Jwt\Contracts\Signer;
use Dracarys\Jwt\Signer\Hmac;

class Sha256 extends Hmac implements Signer
{
    public function algorithm(): string
    {
        return 'sha256';
    }

    public function id(): string
    {
        return 'HS256';
    }
}