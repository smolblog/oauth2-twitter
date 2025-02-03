<?php

namespace Smolblog\OAuth2\Client\Test\Provider;

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
        'pkceVerifier' => 'ENuF7brJJNM5v-dEROtJf.Uee3kTO-GqNQ33fyuY33oixZXo9Vxiomml8-~3ulU9xu4xr_rj1weIer9UYu1JEzK_ZuDUtXe-zHi_2b6Eu41c~HEhzIlV6_QOQWeuvlyh',
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
        self::assertEquals('Q7tD_xw-1L6mtr1RgNQ6-ZHCqA2mRg8_5_OqERLrJtE', $query['code_challenge']);
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

        self::assertStringStartsWith('https://api.twitter.com/2/users/me', $url);
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

        $provider = $this
            ->getMockBuilder(TwitterProvider::class)
            ->onlyMethods(['fetchResourceOwnerDetails'])
            ->setConstructorArgs([[
                'clientId' => 'mock_client_id',
                'clientSecret' => 'mock_secret',
                'redirectUri' => 'none',
                'pkceVerifier' => 'ENuF7brJJNM5v-dEROtJf.Uee3kTO-GqNQ33fyuY33oixZXo9Vxiomml8-~3ulU9xu4xr_rj1weIer9UYu1JEzK_ZuDUtXe-zHi_2b6Eu41c~HEhzIlV6_QOQWeuvlyh',
            ]])
            ->getMock();
        $provider->expects($this->once())->method('fetchResourceOwnerDetails')->willReturn($response);

        // Execute
        $user = $provider->getResourceOwner($token);

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

        $stream = $this->createMock('GuzzleHttp\Psr7\Stream');
        $stream->method('__toString')->willReturn($error_json);

        $response = $this->createMock('GuzzleHttp\Psr7\Response');
        $response->expects($this->once())->method('getHeader')->willReturn(['application/json']);
        $response->expects($this->once())->method('getBody')->willReturn($stream);

        $provider = $this
            ->getMockBuilder(TwitterProvider::class)
            ->onlyMethods(['getResponse'])
            ->setConstructorArgs([[
                'clientId' => 'mock_client_id',
                'clientSecret' => 'mock_secret',
                'redirectUri' => 'none',
                'pkceVerifier' => 'ENuF7brJJNM5v-dEROtJf.Uee3kTO-GqNQ33fyuY33oixZXo9Vxiomml8-~3ulU9xu4xr_rj1weIer9UYu1JEzK_ZuDUtXe-zHi_2b6Eu41c~HEhzIlV6_QOQWeuvlyh',
            ]])
            ->getMock();
        $provider->expects($this->once())->method('getResponse')->willReturn($response);


        $token = $this->mockAccessToken();

        // Expect
        $this->expectException(IdentityProviderException::class);

        // Execute
        $user = $provider->getResourceOwner($token);
    }

    public function testVerifierGeneration(): void
    {
        $verifier = $this->provider->generatePkceVerifier();
        $match_result = preg_match('/^[A-Za-z0-9\-._~]{43,128}$/', $verifier);

        self::assertEquals(1, $match_result);
    }

    public function testChallengeGeneration(): void
    {
        $tests = [
        'g0sseWY2Gp772L_Xu7T1tHkeqRGAOk_9JnU9gFYCmKkVbkFUHu5izyZEivpxDsZU-r40geolIbX64zEvQ7Y4SOYwKL9drG9OF2g1kTB.PJ7nHPbVLFJFL-ziSv6KclSK'
        => 'hzRLCtPmWN3w_EVqGW19ARrMaXZBwYrpnTMkelrYIv4',
        'd_O4i_N0nDZdsjl6JGE.vYoIi-Yr8lXcEYWUKXbjwojf8VtMaTmOSwJJYQ5n5NYz2BrdKSQFkLei3sSzP0dygP8vUkH3rP-dEBl9l5rvFAUXtjsTXUusxwRTisOUPe~Y'
        => 'Lk5oLe4qImaZKgQbT4ICB9rfD5Hy4ozjydlCP_9nPlo',
        'H5MmPYr8-j.GHXGzaN.Ck8LFh-kmeK_Q6xgUZfOSYkYJHKObUJgtP0xcLCkAySnMBQ~-L-RUUfdNr7r2kT1-9Mpabf5wmoBbPRft.T8HFUiyuVCd4KcX2wRGfc1evspn'
        => 'e5KT8_NuYwqcBGkdv3t1Wk-QnbozLkjSaFXKfvDp0nU',
        'D4R-xl8r_6slynxksZhCSbwj5fDB2Hdk8ZzfdW8iWqqbOx7A0oP_XCffIatxBR~J0JYAddxcpIBshuNOTxwUTXhm~24OZWAzmnn-s5FOnOK~mnetlfvDeH6cjhHg~H0-'
        => 'NA7eMVS9lXYsvSWA1T2wFXfxNK8Yx-RttVo9iwmQ2FM',
        'Fk0SY30MvDDXCfwO8TiHz0cFADb3sP8-DqCDysiH7iY4NI_sVHW8Bbyl1sypVY61m4fGv4VzEX.ASdir4BRfcD..I70mINH~_L-g0_Y9xLXD9Di0fYu0psevbxm0yh~w'
        => 'VPKX0gnLeTzjM-UJ5Mc5ZR5VGQzh8ukr_RbFzbfYJ30',
        ];

        foreach ($tests as $verifier => $expected) {
            self::assertEquals($expected, $this->provider->generatePkceChallenge($verifier));
        }
    }

    private function mockAccessToken(): AccessToken
    {
        return new AccessToken([
            'access_token' => 'mock_access_token',
        ]);
    }
}
