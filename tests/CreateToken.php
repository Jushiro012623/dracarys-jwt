<?php
require __DIR__ . '/../vendor/autoload.php';

use Dracarys\Jwt\Configuration;
use Dracarys\Jwt\Signer\Rsa\Sha256;
use Dracarys\Jwt\Signer\Hmac\Sha256 as HmacSha256;
use Dracarys\Jwt\Token\Builder;
use Dracarys\Jwt\Token\TokenData;
use Dracarys\Jwt\Token\Parser;
use Dracarys\Jwt\Validation\Validator;
use Dracarys\Jwt\Signer\OpenSSL;
use Dracarys\Jwt\Signer\Symmetric;

$privateKey = file_get_contents(__DIR__ . '/private/private.pem');
$publicKey = file_get_contents(__DIR__ . '/public/public.pem');

$secretKey = file_get_contents(__DIR__ . '/private/key.txt');

$symmetric = Configuration::symmetric(new HmacSha256(), new Symmetric($secretKey));
$asymmetric = Configuration::asymmetric(new Sha256(), new OpenSSL($privateKey, $publicKey));

function createToken($config)
{
    $claims = new TokenData([
        'aud' => 'https://example.com',
        'iss' => 'https://example.com',
        'sub' => '1234567890',
        'iat' => time(),
    ]);

    $headers = new TokenData([]);
    $token = Builder::fromConfig($config)
        ->withClaims($claims)
        ->withClaims(['role' => 'tester'])
        ->withHeaders($headers)
        ->sign();

    return $token;
}

function parseToken($token)
{
    $parser = new Parser();
    return $parser->parse($token->toString());
}

function verifyToken($token, $config)
{
    $validator = Validator::fromToken($token)
        ->permittedFor('https://example.com')
        ->issuedBy('https://example.com')
        ->signedWith($config->signer(), $config->verificationKey())
        ->custom(fn($token) => $token->claims()->get('role') === 'tester')
        ->relatedTo(1234567890);

    !empty($validator->errors()) && var_dump($validator->errors());

    try {
        $validator->assert();
    } catch (\Exception $e) {
        echo $e->getMessage() . PHP_EOL;
    }

}

$asymmetricToken = createToken($asymmetric);
$symmetricToken = createToken($symmetric);

$parseAsymmetricToken = parseToken($asymmetricToken);
$parseSymmetricToken = parseToken($symmetricToken);


verifyToken($parseAsymmetricToken, $asymmetric);
verifyToken($parseSymmetricToken, $symmetric);


echo PHP_EOL;
echo "ASYMMETRIC TOKEN: " . "\033[34m{$asymmetricToken->toString()}\033[0m" . PHP_EOL;
echo PHP_EOL;
echo "SYMMETRIC TOKEN: " . "\033[34m{$symmetricToken->toString()}\033[0m" . PHP_EOL;
