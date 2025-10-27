<?php
require __DIR__ . '/../../vendor/autoload.php';

use Dracarys\Jwt\Configuration;
use Dracarys\Jwt\Signer\Hmac\Sha256;
use Dracarys\Jwt\Token\Builder;
use Dracarys\Jwt\Token\TokenData;
use Dracarys\Jwt\Token\Parser;
use Dracarys\Jwt\Validation\Validator;
use Dracarys\Jwt\Contracts\Token;

$config = Configuration::symmetric(new Sha256(), 'secret');

$claims = new TokenData([
    'aud' => 'https://example.com',
    'iss' => 'https://example.com',
    'sub' => '1234567890',
    'iat' => time(),
]);

$headers = new TokenData([
    'alg' => 'none'
]);

$token = Builder::fromConfig($config)
    ->withClaims($claims)
    ->withClaims(['role' => 'tester'])
    ->withHeaders($headers)
    ->sign();

echo "TOKEN " . $token->toString() . PHP_EOL;

$parser = new Parser();
$parsedToken = $parser->parse('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2V4YW1wbGUuY29tIiwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLmNvbSIsInN1YiI6IjEyMzQ1Njc4OTAiLCJpYXQiOjE3NjEyMTE5NjUsInRlc3QiOiJ0ZXN0ZXIifQ.darr0NXgGA8PWoVnY0keXxTLTsrjyafN_sTAiAI3VOg');
function isRoleTester(Token $token): bool
{
    return $token->claims()->get('test') === 'roam' ;
}

Validator::fromToken($parsedToken)
    ->permittedFor('https://example.com')
    ->issuedBy('https://example.com')
    ->signedWith($config->signer(), $config->verificationKey())
    ->custom(fn($token) => isRoleTester($token))
    ->relatedTo(1234567890)
    ->assert();
