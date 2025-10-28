# Dracarys JWT

A lightweight and modern PHP JSON Web Token (JWT) library built for PHP 8.3+. This library provides a clean and
intuitive API for creating, parsing, and validating JWT tokens with support for both symmetric (HMAC) and asymmetric (
RSA) signing algorithms.

## Features

- ✅ **Modern PHP**: Requires PHP 8.0+ with full type safety
- ✅ **Multiple Algorithms**: Support for HMAC SHA-256 and RSA SHA-256 signing
- ✅ **Symmetric & Asymmetric**: Both HMAC (shared secret) and RSA (public/private key) encryption
- ✅ **Token Validation**: Comprehensive validation with custom rules
- ✅ **Standard Claims**: Full support for JWT standard claims (iss, aud, sub, iat, exp, nbf, jti)
- ✅ **Custom Claims**: Add your own custom claims to tokens
- ✅ **Fluent API**: Clean, readable method chaining
- ✅ **No Dependencies**: Lightweight with minimal external dependencies

## Installation

Install via Composer:

```bash
composer require dracarys/jwt
```

## Requirements

- PHP 8.0+

# Quick Start

## Symmetric Token Issuing

```php
<?php

use Dracarys\Jwt\Configuration;
use Dracarys\Jwt\Signer\Hmac\Sha256;
use Dracarys\Jwt\Signer\Symmetric;
use Dracarys\Jwt\Token\Builder;
use Dracarys\Jwt\Token\TokenData;
use Dracarys\Jwt\Token\Parser;
use Dracarys\Jwt\Validation\Validator;

// Configuration with symmetric key
$secretKey = 'your-secret-key-here';
$config = Configuration::symmetric(
    new Sha256(), 
    new Symmetric($secretKey)
);

// Create a token
$claims = new TokenData([
    'iss' => 'https://your-domain.com',
    'aud' => 'https://your-app.com',
    'sub' => 'user123',
    'iat' => time(),
    'exp' => time() + 3600, // 1 hour expiration
]);

$headers = new TokenData([
    'foo' => 'bar'
]);

$token = Builder::fromConfig($config)
    ->withClaims($claims)
    ->withClaims(['role' => 'admin', 'permissions' => ['read', 'write']])
    ->withHeaders($headers)
    ->sign();

echo $token->toString(); // "eyyJ0eXAiOiJKV1QiLC..."
```

## Asymmetric Token Issuing

```php
<?php

use Dracarys\Jwt\Configuration;
use Dracarys\Jwt\Signer\Rsa\Sha256;
use Dracarys\Jwt\Signer\OpenSSL;

// Load your RSA keys
$privateKey = file_get_contents('/path/to/private.pem');
$publicKey = file_get_contents('/path/to/public.pem');

// Configuration with RSA keys
$config = Configuration::asymmetric(
    new Sha256(),
    new OpenSSL($privateKey, $publicKey)
);

// Create token (same as symmetric example)
$token = Builder::fromConfig($config)
    ->withClaims($claims)
    ->sign();
```

## Parsing a Token

```php
<?php

// Parse a token string
$parser = new Parser();
try {
    $parsedToken = $parser->parse('eyyJ0eXAiOiJKV1QiLC...');
}catch (Exception $e) {
    echo "Unable to parse token string " . $e->getMessage();
}
```
```php
<?php

// Parse a token string
$parser = new Parser();
$parsedToken = $parser->parse('eyyJ0eXAiOiJKV1QiLC...');

// Validate the token
$validator = Validator::fromToken($parsedToken)
    ->permittedFor('https://your-app.com')
    ->issuedBy('https://your-domain.com')
    ->signedWith($config->signer(), $config->verificationKey())
    ->relatedTo('user123')
    ->custom(fn($token) => $token->claims()->get('role') === 'admin');

// Check for validation errors
if (!empty($validator->errors())) {
    foreach ($validator->errors() as $error) {
        echo "Validation error: " . $error . "\n";
    }
}

// Assert all validations pass (throws exception on failure)
try {
    $validator->assert();
    echo "Token is valid!";
} catch (TokenValidationException $e) {
    echo "Token validation failed: " . $e->getMessage();
}

//OR Checks for validation errors and returns boolean
echo $validator->validate() ? "Token is valid!" : "Token validation failed";

```
## API Reference
### Configuration
Create configurations for different signing methods:
```php
// Symmetric (HMAC)
$config = Configuration::symmetric($signer, $key);

// Asymmetric (RSA)
$config = Configuration::asymmetric($signer, $key);
```
### Token Builder
Build tokens with claims and headers:
```php
$token = Builder::fromConfig($config)
    ->withClaims($tokenData)           // Add claims from TokenData object
    ->withClaims(['key' => 'value'])   // Add individual claims
    ->withHeaders($headerData)         // Add custom headers
    ->sign();                          // Sign and create the token
```
### Token Validation
Validate tokens with built-in and custom rules:
```php
$validator = Validator::fromToken($token)
    ->permittedFor($audience)          // Check 'aud' claim
    ->issuedBy(...$issuers)           // Check 'iss' claim
    ->relatedTo($subject)             // Check 'sub' claim
    ->identifiedBy($jti)              // Check 'jti' claim
    ->signedWith($signer, $key)       // Verify signature
    ->custom($customCallback);        // Custom validation logic
```

### Token Creation, Parsing, and Validation from Configuration
Create tokens with claims and headers:
```php
    $config = Configuration::symmetric(new Sha256(), new Symmetric($secretKey));
    
    //Issuing a token 
    $claims = new TokenData([
        'foo' => 'bar'
        ...
    ]);
    
    $headers = new TokenData([...]);
    
    $token = $config->createToken($claims, $headers)->toString();
    
    $parsedToken = $config->parseToken($token);
    
    //Validate the token
    $validator = Validator::fromToken($parsedToken)
        ...
        ->permittedFor('https://your-app.com')
        
     try {
        $validator->assert();
        echo "Token is valid!";
    } catch (TokenValidationException $e) {
        echo "Token validation failed: " . $e->getMessage();
    }
     
        
     

```
### Standard JWT Claims
The library supports all standard JWT claims:
- iss (Issuer): Who issued the token
- sub (Subject): Who the token is about
- aud (Audience): Who the token is intended for
- exp (Expiration): When the token expires
- nbf (Not Before): When the token becomes valid
- iat (Issued At): When the token was issued
- jti (JWT ID): Unique identifier for the token

### Supported Algorithms
### HMAC (Symmetric)
- Dracarys\Jwt\Signer\Hmac\Sha256
### RSA (Asymmetric)
### Dracarys\Jwt\Signer\Rsa\Sha256

## Security Considerations
1. **Keep your keys secure**: Never expose private keys or secrets in your code
2. **Use strong secrets**: For HMAC, use a strong, random secret key
3. **Validate tokens properly**: Always validate tokens before trusting their contents
4. **Set appropriate expiration times**: Don't create tokens that live forever
5. **Use HTTPS**: Always transmit tokens over secure connections

## License
This project is licensed under the MIT License.
## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
## Support
- **Issues**: [GitHub Issues](https://github.com/jushiro012623/dracarys-jwt/issues)
- **Source**: [GitHub Repository](https://github.com/jushiro012623/dracarys-jwt)

## Author
**Ivan Macabontoc**
- Email: ivanallen64@gmail.com