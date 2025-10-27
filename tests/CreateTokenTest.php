<?php

use PHPUnit\Framework\TestCase;
use Dracarys\Jwt\Token\Builder;
use Dracarys\Jwt\Token\TokenData;
use Dracarys\Jwt\Signer\Hmac\Sha256;
use Dracarys\Jwt\Contracts\UnencryptedToken;
use Dracarys\Jwt\Token\Jwt;

class CreateTokenTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();
        $this->symmetric = \Dracarys\Jwt\Configuration::symmetric(new Sha256(), 'secret');
    }
    private function createToken(): string
    {
        $claims = new TokenData([
            'aud' => 'https://example.com',
            'iss' => 'https://example.com',
            'sub' => '1234567890',
            'role' => 'tester',
            'iat' => time(),
        ]);

        $headers = new TokenData([]);

        $token = $this->symmetric->createToken($claims, $headers);

        $this->assertIsString($token->toString());
        $this->assertNotEmpty($token->toString());

        return $token->toString();
    }

    public function testItParseValidToken()
    {
        $token = $this->createToken();

        $parser = $this->symmetric->parser();
        $this->assertInstanceOf(UnencryptedToken::class, $parser->parse($token), "Parsed token must be an instance of Token");;

        $parsed = $parser->parse($token);

        $this->assertIsObject($parsed, "Parsed token must be an object");
        $this->assertSame('tester', $parsed->claims()->get('role'), "Claim 'role' must be tester");

    }

    public function testItFailsOnInvalidToken()
    {
        $token = "invalid.token.string";
        $parser = $this->symmetric->parser();

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Failed to decode');

        $parser->parse($token);

    }

    public function testItCanValidateToken()
    {
        $token = $this->createToken();

        $parser = $this->symmetric->parser();
        $parsedToken = $parser->parse($token);

        $validator = $this->symmetric->validator($parsedToken)
            ->permittedFor('https://example.com')
            ->issuedBy('https://example.com')
            ->signedWith($this->symmetric->signer(), $this->symmetric->verificationKey())
            ->relatedTo(1234567890);

        $this->assertEmpty($validator->errors());
        $this->assertTrue($validator->validate());
        $validator->assert();
    }

    public function testItFailsIfClaimsIsMissing()
    {
        $token = $this->createToken();

        $parser = $this->symmetric->parser();
        $parsedToken = $parser->parse($token);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Token validation failed');

        $validator = $this->symmetric->validator($parsedToken);
        $validator = $validator->permittedFor('https://example.com')
            ->issuedBy('https://example.com')
            ->signedWith($this->symmetric->signer(), $this->symmetric->verificationKey())
            ->custom(fn($token) => $token->claims()->has('jti'), 'Jwt id is missing')
            ->relatedTo(1234567890);

        $this->assertNotEmpty($validator->errors());
        $this->assertFalse($validator->validate());
        $validator->assert();
    }
}