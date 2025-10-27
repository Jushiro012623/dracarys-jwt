<?php
namespace Dracarys\Test;
use Dracarys\Jwt\Contracts\UnencryptedToken;

class AsymmetricJwtTest extends JwtTestCase
{
    public function testCanCreateAndParseToken()
    {
        $token = $this->asymmetric->createToken($this->claims, $this->headers);
        $this->assertIsString($token->toString());
        $this->assertNotEmpty($token->toString());

        $parser = $this->asymmetric->parser();
        $this->assertInstanceOf(UnencryptedToken::class, $parser->parse($token->toString()));

        $parsed = $parser->parse($token->toString());

        $this->assertSame('tester', $parsed->claims()->get('role'));
    }

    public function testValidationPasses()
    {
        $token = $this->asymmetric->createToken($this->claims, $this->headers);
        $parsed = $this->asymmetric->parser()->parse($token->toString());

        $validator = $this->asymmetric->validator($parsed)
            ->permittedFor('https://example.com')
            ->issuedBy('https://example.com')
            ->signedWith($this->asymmetric->signer(), $this->asymmetric->verificationKey())
            ->relatedTo(1234567890);

        $this->assertTrue($validator->validate());
        $validator->assert();
    }
}
