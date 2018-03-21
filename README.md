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
<?php
use Coercive\Security\Token\Token;

# REQUIRED : if not, Token throws you an exception
session_start();

# INIT
$Token = new Token('mySalt0123');

# CREATE a token
$sMyKey = $Token->create('example');

# SEND this token with a form (for example)
# and test like this
if( $Token->verify( $sMyKey , 'example' ) ) {
    echo 'Good token !';
    $Token->delete('example');
} else {
    die('Wrong token detected');
}

# For form load by AJAX or other complex detection
$Token->verify( $sMyKey , 'example', 'http://www.my-custom-referer')
# OR
$Token->verify( $sMyKey , 'example', [
    'http://www.my-custom-referer-1',
    'http://www.my-custom-referer-2',
    'http://www.my-custom-referer-3'
])

```
