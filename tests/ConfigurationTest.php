<?php

use Dracarys\Jwt\Signer\Hmac\Sha256;

class ConfigurationTest extends \PHPUnit\Framework\TestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->symmetric = \Dracarys\Jwt\Configuration::symmetric(new Sha256(), 'secret');
    }

    public function testSignerIsConfiguredCorrectly()
    {
        $this->assertEquals((new Sha256())->id(), $this->symmetric->signer()->id());
        $this->assertInstanceOf(Sha256::class, $this->symmetric->signer());;
    }

    public function testSigningKeyIsConfiguredCorrectly()
    {
        $this->assertEquals('secret', $this->symmetric->signingKey());
    }

    public function testVerificationKeyIsConfiguredCorrectly()
    {
        $this->assertEquals('secret', $this->symmetric->verificationKey());
    }

}