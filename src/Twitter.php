<?php
/**
 * This file is part of the smolblog/oauth2-twitter library
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 * @copyright Copyright (c) Evan Hildreth <me@eph.me> (on behalf of the Smolblog project)
 * @license http://opensource.org/licenses/MIT MIT
 * @link https://packagist.org/packages/smolblog/oauth2-twitter Packagist
 * @link https://github.com/smolblog/oauth2-twitter GitHub
 */

namespace Smolblog\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RandomLib\Factory as RandomLibFactory;

/**
 * Represents a Twitter OAuth2 service provider (authorization server).
 *
 * @link http://tools.ietf.org/html/rfc6749#section-1.1 Roles (RFC 6749, §1.1)
 */
class Twitter extends AbstractProvider
{
    use BearerAuthorizationTrait;

    /**
     * In addition to state, store a PKCE verifier that will be used when
     * getting the authorization token.
     *
     * @link https://www.oauth.com/oauth2-servers/pkce/authorization-code-exchange/
     *
     * @var string
     */
    protected string $pkce_verifier;

    public function getPkceVerifier(): string
    {
        if (!isset($this->pkce_verifier)) {
            $this->pkce_verifier = $this->generatePkceVerifier();
        }

        return $this->pkce_verifier;
    }

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl(): string
    {
        return 'https://twitter.com/i/oauth2/authorize';
    }

    protected function getAuthorizationParameters(array $options): array
    {
        if (!isset($options['code_challenge'])) {
            $verifier = $options['pkce_verifier'] ?? $this->getPkceVerifier();

            $options['code_challenge'] = $this->base64Urlencode(hash('sha256', $verifier));
            $options['code_challenge_method'] = 'S256';
        }

        return parent::getAuthorizationParameters($options);
    }

    /**
     * Returns a prepared request for requesting an access token. Overridden
     * to add the required headers for Twitter
     *
     * @param array $params Query string parameters
     * @return RequestInterface
     */
    protected function getAccessTokenRequest(array $params): RequestInterface
    {
        $request = parent::getAccessTokenRequest($params);

        $token_string = base64_encode($this->clientId . ':' . $this->clientSecret);

        return $request->withHeader('Authorization', "Basic $token_string");
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params): string
    {
        return 'https://api.twitter.com/2/oauth2/token';
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token): string
    {
        return 'https://api.twitter.com/2/users/me';
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes(): array
    {
        return [
            'tweet.read',
            'users.read',
                        'offline.access',
        ];
    }

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Contains one space (` `)
     */
    protected function getScopeSeparator(): string
    {
        return ' ';
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data): void
    {
        if (isset($data['data'])) {
            return;
        }

            $error = $data['description'] ?? '';
            $code = $data['code'] ?? 400;

            throw new IdentityProviderException($error, $code, $data);
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return TwitterUser
     */
    protected function createResourceOwner(array $response, AccessToken $token): TwitterUser
    {
            return new TwitterUser($response);
    }

    /**
     * Gives a URL-friendly Base64-encoded version of a string
     *
     * @link https://www.oauth.com/oauth2-servers/pkce/authorization-request/
     *
     * @param string $param String to encode
     * @return string
     */
    private function base64Urlencode(string $param): string
    {
        return rtrim(strtr(base64_encode($param), '+/', '-_'), '=');
    }

    /**
     * Create a PKCE verifier string.
     *
     * @link https://www.oauth.com/oauth2-servers/pkce/authorization-request/
     *
     * @return string
     */
    public function generatePkceVerifier(): string
    {
        $generator = (new RandomLibFactory)->getMediumStrengthGenerator();
        return $generator->generateString(
            $generator->generateInt(43, 128), // Length between 43-128 characters
            '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-._~'
        );
    }
}
