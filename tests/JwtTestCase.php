<?php
namespace Dracarys\Test;

use PHPUnit\Framework\TestCase;
use Dracarys\Jwt\Signer\OpenSSL;
use Dracarys\Jwt\Signer\Hmac\Sha256;
use Dracarys\Jwt\Signer\Rsa\Sha256 as RsaSha256;
use Dracarys\Jwt\Token\TokenData;
use Dracarys\Jwt\Configuration;
abstract class JwtTestCase extends TestCase
{
    protected Configuration $symmetric;
    protected Configuration $asymmetric;
    protected TokenData $claims;
    protected TokenData $headers;

    protected function setUp(): void
    {
        parent::setUp();

        $privateKey = file_get_contents(__DIR__ . '/private.pem');
        $publicKey = file_get_contents(__DIR__ . '/public.pem');

        $this->symmetric = \Dracarys\Jwt\Configuration::symmetric(new Sha256(), 'secret');
        $this->asymmetric = \Dracarys\Jwt\Configuration::asymmetric(new RsaSha256(), new OpenSSL($privateKey, $publicKey));

        $this->claims = new TokenData([
            'aud' => 'https://example.com',
            'iss' => 'https://example.com',
            'sub' => '1234567890',
            'role' => 'tester',
            'iat' => time(),
        ]);

        $this->headers = new TokenData([]);
    }
}