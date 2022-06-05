<?php

namespace Smolblog\OAuth2\Client\Test\Provider;

use Eloquent\Phony\Phpunit\Phony;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use PHPUnit\Framework\TestCase;
use Smolblog\OAuth2\Client\Provider\Twitter as TwitterProvider;

class TwitterTest extends TestCase
{
	/** @var TwitterProvider */
	protected $provider;

	protected function setUp(): void
	{
		$this->provider = new TwitterProvider([
			'clientId' => 'mock_client_id',
			'clientSecret' => 'mock_secret',
			'redirectUri' => 'none',
		]);
	}

  /**
   * @link https://developer.twitter.com/en/docs/authentication/oauth-2-0/authorization-code
   */
	public function testSmipleAuthorizationUrl(): void
	{
		$url = $this->provider->getAuthorizationUrl();
		$uri = parse_url($url);
		parse_str($uri['query'], $query);

		self::assertArrayHasKey('response_type', $query);
		self::assertArrayHasKey('client_id', $query);
		self::assertArrayHasKey('redirect_uri', $query);
		self::assertArrayHasKey('state', $query);
		self::assertArrayHasKey('code_challenge', $query);
		self::assertArrayHasKey('code_challenge_method', $query);

		self::assertEquals('code', $query['response_type']);
		self::assertEquals('mock_client_id', $query['client_id']);
		self::assertEquals('none', $query['redirect_uri']);
    self::assertEquals('S256', $query['code_challenge_method']);

		self::assertStringContainsString('tweet.read', $query['scope']);
		self::assertStringContainsString('users.read', $query['scope']);
		self::assertStringContainsString('offline.access', $query['scope']);

		self::assertNotEmpty($this->provider->getState());
	}

	public function testBaseAccessTokenUrl(): void
	{
		$url = $this->provider->getBaseAccessTokenUrl([]);
		$uri = parse_url($url);

		self::assertEquals('/2/oauth2/token', $uri['path']);
	}

	public function testResourceOwnerDetailsUrl(): void
	{
		$token = $this->mockAccessToken();

		$url = $this->provider->getResourceOwnerDetailsUrl($token);

		self::assertEquals('https://api.twitter.com/2/users/me', $url);
	}

	public function testUserData(): void
	{
		// Mock
		$response = [
      "data" => [
        "id" => "1132750396936589312",
        "name" => "Smolblog",
        "username" => "_smolblog",
      ]
    ];

		$token = $this->mockAccessToken();

		$provider = Phony::partialMock(TwitterProvider::class);
		$provider->fetchResourceOwnerDetails->returns($response);
		$google = $provider->get();

		// Execute
		$user = $google->getResourceOwner($token);

		// Verify
		Phony::inOrder(
			$provider->fetchResourceOwnerDetails->called()
		);

		self::assertInstanceOf(ResourceOwnerInterface::class, $user);

		self::assertEquals(1132750396936589312, $user->getId());
		self::assertEquals('Smolblog', $user->getName());
    self::assertEquals('_smolblog', $user->getUsername());

		$user = $user->toArray();

		self::assertArrayHasKey('id', $user);
		self::assertArrayHasKey('name', $user);
		self::assertArrayHasKey('username', $user);
	}

	public function testErrorResponse(): void
	{
		// Mock
		$error_json = '{
      "title": "Unauthorized",
      "type": "about:blank",
      "status": 401,
      "detail": "Unauthorized"
    }';

		$stream = Phony::mock('GuzzleHttp\Psr7\Stream');
		$stream->__toString->returns($error_json);

		$response = Phony::mock('GuzzleHttp\Psr7\Response');
		$response->getHeader->returns(['application/json']);
		$response->getBody->returns($stream);

		$provider = Phony::partialMock(TwitterProvider::class);
		$provider->getResponse->returns($response);

		$google = $provider->get();

		$token = $this->mockAccessToken();

		// Expect
		$this->expectException(IdentityProviderException::class);

		// Execute
		$user = $google->getResourceOwner($token);

		// Verify
		Phony::inOrder(
			$provider->getResponse->calledWith($this->instanceOf('GuzzleHttp\Psr7\Request')),
			$response->getHeader->called(),
			$response->getBody->called()
		);
	}

  public function testVerifierGeneration(): void {
    $verifier = $this->provider->generatePkceVerifier();
    $match_result = preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $verifier);

    self::assertEquals(1, $match_result);
  }

	private function mockAccessToken(): AccessToken
	{
		return new AccessToken([
			'access_token' => 'mock_access_token',
		]);
	}
}