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
use Coercive\Security\Token

# REQUIRED : if not, Token throws you an exception
session_start();

# Create a salt string or integer
$sMyUniqSalt = 'Hello, this is my project name (for example)';

# INIT
$ObjectToken = new Token( $sMyUniqSalt );

# GET the current token
$sMyToken = $ObjectToken->get();

# MATCH a token with the current
$sWrongToken = 'I am a wrong Token';

if( $ObjectToken->match( $sWrongToken ) ) {
    echo 'Good token !';
} else {
    die('Wrong token detected');
}

# IF YOU CHANGE YOUR ID SESSION
# YOU CAN RE-INIT AN ALREADY INSTANTIATED TOKEN
$ObjectToken->init();

```
