Coercive Token Security
=======================

Token allows you to calculate a valid token for the current time and the time before or after.
This token is based on the session code, a salt, and time server.

Get
---
```
composer require coercive/token
```

Usage
-----
```php
use Coercive\Security\Token\Token;

# REQUIRED : if not, Token throws you an exception
session_start();

# INIT
$ObjectToken = new Token('This is my personal salt');

# CREATE a token
$sMyToken = $ObjectToken->create('example');

# SEND this token with a form (for example)
# and test like this
if( $ObjectToken->verify( $sMyToken , 'example' ) ) {
    echo 'Good token !';
} else {
    die('Wrong token detected');
}

```
