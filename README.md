# Twitter Provider for OAuth 2.0 Client

This package provides Twitter OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

## Installation

To install, use composer:

```
composer require smolblog/oauth2-twitter
```

## Usage

Usage is the same as The League's OAuth client, using `\Smolblog\OAuth2\Client\Provider\Twitter` as the provider.

### Authorization Code Flow

```php
<?php
session_start();

require_once 'vendor/autoload.php';

$provider = new Smolblog\OAuth2\Client\Provider\Twitter([
	'clientId'          => 'MjVXMnRGVUN5Ym5lcVllcTVKZkk6MTpjaQ',
	'clientSecret'      => 'YDPiM-JsC5xU44P2VijGJRB7zdKB1PckCGjOynXGx9HZM7N6As',
	'redirectUri'       => 'http://oddevan.test/twitter-test/',
]);

if (!isset($_GET['code'])) {
	unset($_SESSION['oauth2state']);
	unset($_SESSION['oauth2verifier']);

	// If we don't have an authorization code then get one
	$authUrl = $provider->getAuthorizationUrl();
	$_SESSION['oauth2state'] = $provider->getState();

	// We also need to store the PKCE Verification code so we can send it with
	// the authorization code request.
	$_SESSION['oauth2verifier'] = $provider->getPkceVerifier();

	header('Location: '.$authUrl);
	exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

	unset($_SESSION['oauth2state']);
	exit('Invalid state');

} else {

	try {

		// Try to get an access token (using the authorization code grant)
		$token = $provider->getAccessToken('authorization_code', [
				'code' => $_GET['code'],
				'code_verifier' => $_SESSION['oauth2verifier'],
		]);

		// Optional: Now you have a token you can look up a users profile data
		// We got an access token, let's now get the user's details
		$user = $provider->getResourceOwner($token);

		// Use these details to create a new profile
		printf('Hello %s!', $user->getName());

	} catch (Exception $e) {
		echo '<pre>';
		print_r($e);
		echo '</pre>';

			// Failed to get user details
			exit('Oh dear...');
	}

	// Use this to interact with an API on the users behalf
	echo $token->getToken();
}
```

## Credits

- [Evan Hildreth](https://github.com/oddevan)

Maintained as part of the [Smolblog](https://smolblog.org/) project.

## License

The Modified 3-clause BSD License (BSD). Please see [License File](https://github.com/smolblog/oauth2-twitter/blob/main/LICENSE.md) for more information.