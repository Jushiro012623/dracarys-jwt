<?php

namespace Dracarys\Jwt\Signer\Rsa;

use Dracarys\Jwt\Contracts\SignerAlgorithm;
use Dracarys\Jwt\Signer\Rsa;
class Sha256 extends Rsa implements SignerAlgorithm
{
    /**
     * Executes the algorithm method to retrieve the designated algorithm constant.
     *
     * @return int Returns the constant value representing the selected algorithm.
     */
    public function algorithm(): int
    {
        return OPENSSL_ALGO_SHA256;
    }

    public function id(): string
    {
        return 'RS256';
    }
}