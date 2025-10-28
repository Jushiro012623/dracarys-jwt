<?php
namespace Dracarys\Test;


use Dracarys\Jwt\Contracts\UnencryptedToken;
use Dracarys\Jwt\Signer\Hmac\Sha256;
use Dracarys\Jwt\Signer\Symmetric;
use Dracarys\Jwt\Token\TokenData;
use PHPUnit\Framework\TestCase;

class ConfigurationTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->symmetric = \Dracarys\Jwt\Configuration::symmetric(new Sha256(), new Symmetric('secret'));
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

    public function createToken(): string
    {
        $claims = new TokenData(['foo' => 'bar']);
        $token = $this->symmetric->createToken($claims)->toString();

        $this->assertNotEmpty($token);
        $this->assertIsString($token);

        return $token;
    }

    public function testCanParseToken()
    {
        $token = $this->createToken();
        $parser =  $this->symmetric->parser();

        $this->assertInstanceOf(UnencryptedToken::class, $parser->parse($token));

        $parsedToken = $parser->parse($token);
        $this->assertSame('bar', $parsedToken->claims()->get('foo'));
    }

    public function testCanValidateToken()
    {
        $token = $this->createToken();
        $parser =  $this->symmetric->parser();
        $parsedToken = $parser->parse($token);

        $validator = $this->symmetric->validator($parsedToken)
        ->custom(fn($token) => $token->claims()->has('foo'), 'Missing foo claim');

        $this->assertTrue($validator->validate());
        $this->assertEmpty($validator->errors());
    }

}