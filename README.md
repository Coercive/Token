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
$Token = new Token(128, 'mySalt0123');

// The first parameter is the length of the random string used in the token
// The second parameter is the custom salt used in the token
// The thirth parameter allow you to specify where the token datas will be store
// The thourth parameter allow you to specify a name for the default global token (if noname)

# CREATE a token
$myKey = $Token->create('example');

# SEND this token with a form (for example)
# and test like this
if( $Token->verify( $myKey , 'example' ) ) {
    echo 'Good token !';
    $Token->delete('example');
} else {
    die('Wrong token detected');
}

```

For form load by AJAX or other complex detection

```php
<?php

$Token->verify( $myKey , 'example', 'http://www.my-custom-referer')

# OR

$Token->verify( $myKey , 'example', [
    'http://www.my-custom-referer-1',
    'http://www.my-custom-referer-2',
    'http://www.my-custom-referer-3'
])
```

Get token for others usages

```php
<?php

# A basic random string
Token::rand(256)

# A uniq id based on session, salt, random string...
$Token->uniqId()

# A basic (unsafe) token based on datetime
$Token->timer()

# You can use a crypt for customise the timer token
$crypt = 1234567890;
$Token->timer(crypt)


```
