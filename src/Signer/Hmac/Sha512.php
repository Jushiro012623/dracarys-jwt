<?php

namespace Dracarys\Jwt\Signer\Hmac;

use Dracarys\Jwt\Contracts\SignerAlgorithm;
use Dracarys\Jwt\Signer\Hmac;

class Sha512 extends Hmac implements SignerAlgorithm
{
    public function algorithm(): string
    {
        return 'sha512';
    }

    public function id(): string
    {
        return 'HS512';
    }

}