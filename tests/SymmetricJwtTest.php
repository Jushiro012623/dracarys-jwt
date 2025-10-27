<?php
namespace Dracarys\Test;

use Dracarys\Jwt\Contracts\UnencryptedToken;

class SymmetricJwtTest extends JwtTestCase
{
    public function testCanCreateAndParseToken()
    {
        $token = $this->symmetric->createToken($this->claims, $this->headers);
        $this->assertIsString($token->toString());
        $this->assertNotEmpty($token->toString());

        $parser = $this->symmetric->parser();
        $this->assertInstanceOf(UnencryptedToken::class, $parser->parse($token->toString()));

        $parsed = $parser->parse($token->toString());

        $this->assertSame('tester', $parsed->claims()->get('role'));
    }

    public function testValidationPassesWithValidClaims()
    {
        $token = $this->symmetric->createToken($this->claims, $this->headers);
        $parsed = $this->symmetric->parser()->parse($token->toString());

        $validator = $this->symmetric->validator($parsed)
            ->permittedFor('https://example.com')
            ->issuedBy('https://example.com')
            ->signedWith($this->symmetric->signer(), $this->symmetric->verificationKey())
            ->relatedTo(1234567890);

        $this->assertTrue($validator->validate());
        $validator->assert();
    }

    public function testValidationFailsWhenClaimMissing()
    {
        $token = $this->symmetric->createToken($this->claims, $this->headers);
        $parsed = $this->symmetric->parser()->parse($token->toString());

        $validator = $this->symmetric->validator($parsed)
            ->custom(fn($token) => $token->claims()->has('jti'), 'Jwt ID missing');

        $this->assertFalse($validator->validate());
        $this->assertNotEmpty($validator->errors());
    }

    public function testFailsOnInvalidTokenString()
    {
        $parser = $this->symmetric->parser();

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Failed to decode');

        $parser->parse('invalid.token.string');
    }
}
