<?php

declare(strict_types=1);

namespace NobleId\SignIn;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\GenericProvider;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

/**
 * "Sign in with NobleID" for PHP servers.
 *
 * A thin layer over league/oauth2-client (authorization URL, PKCE S256, code
 * and refresh grants) and firebase/php-jwt (ES256 ID-token signatures against
 * the provider's JWKS). It adds what those libraries leave to you: discovery,
 * state and nonce, the RFC 9207 `iss` check on every callback, ID-token claim
 * checks, userinfo, the works list and revocation. It does no cryptography of
 * its own.
 *
 * Keep tokens on your server. Store the transaction returned by startSignIn()
 * in your server-side session and pass it back, once, to finishSignIn().
 */
final class NobleIdClient
{
    public const ISSUER = 'https://id.nobleid.org';
    public const DEFAULT_SCOPE = 'openid profile email';

    /** A sign-in that takes longer than this is refused (seconds). */
    public const MAX_FLOW_AGE = 600;

    /** Allowed clock skew when checking exp / iat / auth_time (seconds). */
    public const LEEWAY = 60;

    private const LOCAL_HOSTS = ['localhost', '127.0.0.1'];
    private const CACHE_TTL = 3600;

    /** Minimum gap between two JWKS re-fetches caused by an unknown kid (seconds). */
    private const JWKS_REFETCH_COOLDOWN = 30;

    /** When this instance last re-fetched the JWKS for an unknown kid. */
    private ?int $lastJwksRefetch = null;

    /** @var array<string, \Firebase\JWT\Key>|null */
    private ?array $keys = null;

    /**
     * @param array<string, mixed> $metadata validated discovery document
     */
    private function __construct(
        private readonly array $metadata,
        private readonly string $clientId,
        #[\SensitiveParameter] private readonly ?string $clientSecret,
        private readonly string $redirectUri,
        private readonly string $clientAuth,
        private readonly ClientInterface $http,
        private readonly ?object $cache,
    ) {
    }

    /**
     * Fetch the provider's discovery document and create a client.
     *
     * Options:
     *  - clientId      (required) your client id, nbcl_...
     *  - clientSecret  confidential clients only; read it from the environment
     *  - redirectUri   (required) exactly as registered
     *  - issuer        defaults to https://id.nobleid.org; http is accepted only
     *                  for localhost / 127.0.0.1 (a local mock)
     *  - clientAuth    client_secret_basic (default with a secret) | client_secret_post | none
     *  - httpClient    a GuzzleHttp\ClientInterface (default: 10 s timeout, no redirects);
     *                  your own must also set allow_redirects => false
     *  - cache         any PSR-16 cache (get/set) for the discovery document and JWKS
     *
     * @param array<string, mixed> $options
     */
    public static function discover(#[\SensitiveParameter] array $options): self
    {
        $clientId = (string) ($options['clientId'] ?? '');
        $redirectUri = (string) ($options['redirectUri'] ?? '');
        $secret = isset($options['clientSecret']) && $options['clientSecret'] !== '' ? (string) $options['clientSecret'] : null;
        $issuer = (string) ($options['issuer'] ?? self::ISSUER);
        if ($clientId === '') {
            throw new NobleIdException('invalid_request', 'clientId is required');
        }
        if ($redirectUri === '') {
            throw new NobleIdException('invalid_request', 'redirectUri is required');
        }
        $auth = (string) ($options['clientAuth'] ?? ($secret !== null ? 'client_secret_basic' : 'none'));
        if (!in_array($auth, ['client_secret_basic', 'client_secret_post', 'none'], true)) {
            throw new NobleIdException('invalid_request', 'clientAuth must be client_secret_basic, client_secret_post or none');
        }
        if ($auth !== 'none' && $secret === null) {
            throw new NobleIdException('invalid_request', 'clientSecret is required for ' . $auth);
        }
        if ($auth === 'none' && $secret !== null) {
            throw new NobleIdException('invalid_request', 'public clients have no secret');
        }
        $local = self::checkIssuerUrl($issuer);

        $http = $options['httpClient'] ?? new GuzzleClient([
            'timeout' => 10,
            'connect_timeout' => 5,
            'allow_redirects' => false,
            'http_errors' => false,
            'headers' => ['User-Agent' => 'nobleid-signin-php/1.0'],
        ]);
        if (!$http instanceof ClientInterface) {
            throw new NobleIdException('invalid_request', 'httpClient must implement GuzzleHttp\ClientInterface');
        }
        $cache = $options['cache'] ?? null;
        if ($cache !== null && !(is_object($cache) && method_exists($cache, 'get') && method_exists($cache, 'set'))) {
            throw new NobleIdException('invalid_request', 'cache must be a PSR-16 cache');
        }

        $cacheKey = self::cacheKey($issuer, 'discovery');
        $metadata = null;
        if ($cache !== null) {
            $cached = $cache->get($cacheKey);
            $metadata = is_string($cached) ? json_decode($cached, true) : null;
        }
        if (!is_array($metadata)) {
            $metadata = self::getJson($http, $issuer . '/.well-known/openid-configuration');
            self::validateMetadata($metadata, $issuer, $local);
            if ($cache !== null) {
                $cache->set($cacheKey, json_encode($metadata), self::CACHE_TTL);
            }
        } else {
            self::validateMetadata($metadata, $issuer, $local);
        }

        return new self($metadata, $clientId, $secret, $redirectUri, $auth, $http, $cache);
    }

    /** The validated discovery document. */
    public function metadata(): array
    {
        return $this->metadata;
    }

    public function issuer(): string
    {
        return $this->metadata['issuer'];
    }

    /**
     * Build the authorization URL.
     *
     * Returns [url, transaction]. Keep the transaction (state, nonce, PKCE
     * verifier, creation time) in the server-side session, never in a URL or
     * a cookie the browser can read, and pass it to finishSignIn() once.
     *
     * @param array{prompt?: string, login_hint?: string, max_age?: int} $extra
     * @return array{0: string, 1: array<string, mixed>}
     */
    public function startSignIn(string $scope = self::DEFAULT_SCOPE, array $extra = []): array
    {
        $scopes = array_values(array_filter(explode(' ', $scope), static fn ($s) => $s !== ''));
        if (!in_array('openid', $scopes, true)) {
            array_unshift($scopes, 'openid');
        }
        $state = self::random();
        $nonce = self::random();
        $provider = $this->provider();
        $params = [
            'state' => $state,
            'nonce' => $nonce,
            'scope' => $scopes, // joined with a space (scopeSeparator)
            'approval_prompt' => null, // league adds approval_prompt=auto by default; NobleID uses prompt
        ];
        foreach (['prompt', 'login_hint', 'max_age'] as $k) {
            if (isset($extra[$k]) && $extra[$k] !== '') {
                $params[$k] = (string) $extra[$k];
            }
        }
        $url = $provider->getAuthorizationUrl($params);
        $verifier = $provider->getPkceCode();
        if (!is_string($verifier) || $verifier === '') {
            throw new NobleIdException('server_error', 'PKCE was not set up');
        }

        return [$url, [
            'state' => $state,
            'nonce' => $nonce,
            'code_verifier' => $verifier,
            'created_at' => time(),
            'scope' => implode(' ', $scopes),
            'max_age' => isset($extra['max_age']) ? (int) $extra['max_age'] : null,
        ]];
    }

    /**
     * Complete sign-in on the redirect URI.
     *
     * Checks, in this order: a sign-in is in progress, `state` matches, `iss`
     * is the issuer, then surfaces any `error`, then the code is present and
     * the flow is not too old; then exchanges the code with the PKCE verifier
     * and verifies the ID token (ES256 signature via JWKS, iss, aud, exp, nonce).
     *
     * @param array<string, mixed>      $query       the callback's query parameters ($_GET)
     * @param array<string, mixed>|null $transaction what startSignIn() returned; use it once
     * @return array{tokens: array<string, mixed>, claims: array<string, mixed>, scope: list<string>}
     */
    public function finishSignIn(#[\SensitiveParameter] array $query, #[\SensitiveParameter] ?array $transaction): array
    {
        if (!is_array($transaction) || !isset($transaction['state']) || !is_string($transaction['state'])) {
            throw new NobleIdException('invalid_state', 'no sign-in in progress');
        }
        $state = $query['state'] ?? null;
        if (!is_string($state) || !hash_equals($transaction['state'], $state)) {
            throw new NobleIdException('invalid_state', 'state does not match');
        }
        // RFC 9207: the response must name the issuer we started with. Many
        // libraries skip this; it stops mix-up attacks.
        $iss = $query['iss'] ?? null;
        if (!is_string($iss) || $iss !== $this->issuer()) {
            throw new NobleIdException('invalid_issuer', 'the response did not come from the expected issuer');
        }
        if (isset($query['error'])) {
            $error = is_string($query['error']) ? $query['error'] : '';
            $desc = isset($query['error_description']) && is_string($query['error_description']) ? $query['error_description'] : '';
            throw new NobleIdException(self::safeCode($error), self::safeText($desc));
        }
        $code = $query['code'] ?? null;
        if (!is_string($code) || $code === '') {
            throw new NobleIdException('invalid_request', 'no authorization code');
        }
        $age = time() - (int) ($transaction['created_at'] ?? 0);
        if ($age > self::MAX_FLOW_AGE || $age < -self::LEEWAY) {
            throw new NobleIdException('expired', 'sign-in took too long; start again');
        }

        $provider = $this->provider();
        $provider->setPkceCode((string) ($transaction['code_verifier'] ?? ''));
        $token = $this->grant($provider, 'authorization_code', ['code' => $code]);
        $values = $token->getValues();
        $idToken = $values['id_token'] ?? null;
        if (!is_string($idToken) || $idToken === '') {
            throw new NobleIdException('invalid_id_token', 'the token response has no ID token');
        }
        $claims = $this->verifyIdToken(
            $idToken,
            (string) ($transaction['nonce'] ?? ''),
            isset($transaction['max_age']) ? (int) $transaction['max_age'] : null,
        );
        // The user may untick scopes on the consent screen: read what was granted.
        $granted = isset($values['scope']) && is_string($values['scope']) ? $values['scope'] : (string) ($transaction['scope'] ?? 'openid');

        return [
            'tokens' => self::tokenSet($token),
            'claims' => $claims,
            'scope' => array_values(array_filter(explode(' ', $granted), static fn ($s) => $s !== '')),
        ];
    }

    /**
     * Verify an ID token: ES256 only, signature against the JWKS (fetched
     * again on an unknown kid, at most once every 30 seconds), iss, aud (and
     * azp), exp, iat, and the nonce when one is expected. Returns the claims.
     *
     * This is for ID tokens this server received from NobleID's token
     * endpoint itself. It is not for authenticating a caller by a token that
     * a browser or app hands you.
     *
     * @return array<string, mixed>
     */
    public function verifyIdToken(#[\SensitiveParameter] string $jwt, ?string $expectedNonce, ?int $maxAge = null): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new NobleIdException('invalid_id_token', 'malformed ID token');
        }
        $header = json_decode(JWT::urlsafeB64Decode($parts[0]), true);
        if (!is_array($header) || ($header['alg'] ?? null) !== 'ES256') {
            throw new NobleIdException('invalid_id_token', 'ID token must be signed with ES256');
        }
        $kid = isset($header['kid']) && is_string($header['kid']) ? $header['kid'] : null;
        $keys = $this->jwks(false);
        if ($kid === null || !isset($keys[$kid])) {
            // The provider may have rotated its key: fetch the JWKS again, but at
            // most once per cooldown, so tokens with made-up kids cannot turn
            // this client into a JWKS-fetching loop.
            if (!$this->mayRefetchJwks()) {
                throw new NobleIdException('invalid_id_token', 'ID token signed with an unknown key');
            }
            $keys = $this->jwks(true);
        }

        $previousLeeway = JWT::$leeway;
        JWT::$leeway = max(JWT::$leeway, self::LEEWAY);
        try {
            $payload = JWT::decode($jwt, $keys);
        } catch (\Throwable $e) {
            // php-jwt messages describe the failure (signature, expiry, kid), never the token.
            throw new NobleIdException('invalid_id_token', 'ID token rejected: ' . self::safeText($e->getMessage()));
        } finally {
            JWT::$leeway = $previousLeeway;
        }
        $claims = json_decode((string) json_encode($payload), true);
        if (!is_array($claims)) {
            throw new NobleIdException('invalid_id_token', 'ID token claims are not an object');
        }

        if (($claims['iss'] ?? null) !== $this->issuer()) {
            throw new NobleIdException('invalid_id_token', 'unexpected iss');
        }
        $aud = $claims['aud'] ?? null;
        $auds = is_array($aud) ? $aud : [$aud];
        if (!in_array($this->clientId, $auds, true)) {
            throw new NobleIdException('invalid_id_token', 'ID token was issued to another client (aud)');
        }
        if ((count($auds) > 1 || isset($claims['azp'])) && ($claims['azp'] ?? null) !== $this->clientId) {
            throw new NobleIdException('invalid_id_token', 'unexpected azp');
        }
        if (!isset($claims['exp']) || !is_numeric($claims['exp'])) {
            throw new NobleIdException('invalid_id_token', 'ID token has no exp');
        }
        if (!isset($claims['iat']) || !is_numeric($claims['iat'])) {
            throw new NobleIdException('invalid_id_token', 'ID token has no iat');
        }
        if (!isset($claims['sub']) || !is_string($claims['sub']) || $claims['sub'] === '') {
            throw new NobleIdException('invalid_id_token', 'ID token has no sub');
        }
        if ($expectedNonce !== null) {
            $nonce = $claims['nonce'] ?? null;
            if ($expectedNonce === '' || !is_string($nonce) || !hash_equals($expectedNonce, $nonce)) {
                throw new NobleIdException('invalid_id_token', 'nonce does not match');
            }
        }
        if ($maxAge !== null) {
            $authTime = $claims['auth_time'] ?? null;
            if (!is_numeric($authTime) || (int) $authTime + $maxAge + self::LEEWAY < time()) {
                throw new NobleIdException('invalid_id_token', 'authentication is older than max_age');
            }
        }

        return $claims;
    }

    /**
     * Claims from the userinfo endpoint (includes userinfo-only claims such as
     * affiliations, research_interests and verified_authorship_count).
     * `$expectedSub` must be the ID token's sub.
     *
     * @return array<string, mixed>
     */
    public function userinfo(#[\SensitiveParameter] string $accessToken, string $expectedSub): array
    {
        $url = $this->metadata['userinfo_endpoint'] ?? null;
        if (!is_string($url)) {
            throw new NobleIdException('server_error', 'the provider has no userinfo endpoint');
        }
        $info = $this->bearerJson($url, $accessToken);
        if (($info['sub'] ?? null) !== $expectedSub) {
            throw new NobleIdException('invalid_response', 'userinfo is for a different user');
        }

        return $info;
    }

    /**
     * The user's registered works (needs the `works` scope).
     *
     * @return array<string, mixed> {sub, total, limit, offset, works: [...]}
     */
    public function works(#[\SensitiveParameter] string $accessToken, int $limit = 50, int $offset = 0): array
    {
        if ($limit < 1 || $limit > 100 || $offset < 0) {
            throw new NobleIdException('invalid_request', 'limit must be 1..100 and offset >= 0');
        }
        $url = $this->issuer() . '/oauth/works?' . http_build_query(['limit' => $limit, 'offset' => $offset]);

        return $this->bearerJson($url, $accessToken);
    }

    /**
     * Use a refresh token (needs `offline_access`).
     *
     * NobleID rotates refresh tokens: store the returned refresh_token and
     * discard the old one. Presenting a used refresh token again ends the
     * whole session, so never run two refreshes of the same token at once:
     * serialise them per user session (PHP's default file session handler
     * already locks the session for the length of a request). On
     * `invalid_grant`, sign the user out.
     *
     * Refresh-issued ID tokens carry no nonce, auth_time or amr; when one is
     * returned it is verified (signature, iss, aud, exp) and, if `$expectedSub`
     * is given, must be for the same user. Its claims are in `claims`.
     *
     * @return array<string, mixed> token set (+ `claims` when an ID token came back)
     */
    public function refresh(#[\SensitiveParameter] string $refreshToken, ?string $expectedSub = null, ?string $scope = null): array
    {
        $options = ['refresh_token' => $refreshToken];
        if ($scope !== null) {
            $options['scope'] = $scope;
        }
        $token = $this->grant($this->provider(), 'refresh_token', $options);
        $set = self::tokenSet($token);
        $idToken = $token->getValues()['id_token'] ?? null;
        if (is_string($idToken) && $idToken !== '') {
            $claims = $this->verifyIdToken($idToken, null);
            if ($expectedSub !== null && $claims['sub'] !== $expectedSub) {
                throw new NobleIdException('invalid_id_token', 'refreshed ID token is for a different user');
            }
            $set['claims'] = $claims;
        }

        return $set;
    }

    /**
     * Revoke a token (RFC 7009). Revoking a refresh token also ends the access
     * tokens issued from it. NobleID has no end-session endpoint: to sign out,
     * revoke, then clear your own session.
     */
    public function revoke(#[\SensitiveParameter] string $token, ?string $tokenTypeHint = null): void
    {
        $url = $this->metadata['revocation_endpoint'] ?? null;
        if (!is_string($url)) {
            throw new NobleIdException('server_error', 'the provider has no revocation endpoint');
        }
        $form = ['token' => $token];
        if ($tokenTypeHint !== null) {
            $form['token_type_hint'] = $tokenTypeHint;
        }
        $headers = ['Content-Type' => 'application/x-www-form-urlencoded', 'Accept' => 'application/json'];
        if ($this->clientAuth === 'client_secret_basic') {
            $headers['Authorization'] = ClientSecretBasicOptionProvider::header($this->clientId, (string) $this->clientSecret);
        } else {
            $form['client_id'] = $this->clientId;
            if ($this->clientAuth === 'client_secret_post') {
                $form['client_secret'] = (string) $this->clientSecret;
            }
        }
        $res = $this->send('POST', $url, ['headers' => $headers, 'body' => http_build_query($form, '', '&', PHP_QUERY_RFC1738)]);
        if ($res->getStatusCode() !== 200) {
            throw self::errorFrom($res);
        }
    }

    /* ── internals ── */

    private function provider(): GenericProvider
    {
        $collaborators = ['httpClient' => $this->http];
        if ($this->clientAuth === 'client_secret_basic') {
            $collaborators['optionProvider'] = new ClientSecretBasicOptionProvider();
        }

        return new GenericProvider([
            'clientId' => $this->clientId,
            'clientSecret' => $this->clientAuth === 'none' ? null : $this->clientSecret,
            'redirectUri' => $this->redirectUri,
            'urlAuthorize' => $this->metadata['authorization_endpoint'],
            'urlAccessToken' => $this->metadata['token_endpoint'],
            'urlResourceOwnerDetails' => $this->metadata['userinfo_endpoint'] ?? $this->metadata['token_endpoint'],
            'scopeSeparator' => ' ', // league's default is ","
            'pkceMethod' => GenericProvider::PKCE_METHOD_S256, // never plain
            'responseError' => 'error',
        ], $collaborators);
    }

    /** @param array<string, mixed> $options */
    private function grant(GenericProvider $provider, string $grant, #[\SensitiveParameter] array $options): AccessToken
    {
        try {
            $token = $provider->getAccessToken($grant, $options);
        } catch (IdentityProviderException $e) {
            $body = $e->getResponseBody();
            $desc = is_array($body) && isset($body['error_description']) && is_string($body['error_description']) ? $body['error_description'] : '';
            throw new NobleIdException(self::safeCode($e->getMessage()), self::safeText($desc));
        } catch (GuzzleException $e) {
            throw new NobleIdException('server_error', 'could not reach the token endpoint');
        } catch (\UnexpectedValueException $e) {
            throw new NobleIdException('server_error', 'unexpected response from the token endpoint');
        }
        if (!$token instanceof AccessToken) {
            throw new NobleIdException('server_error', 'unexpected token response');
        }
        if (strcasecmp((string) ($token->getValues()['token_type'] ?? ''), 'Bearer') !== 0) {
            throw new NobleIdException('server_error', 'unexpected token_type');
        }

        return $token;
    }

    /** @return array<string, mixed> */
    private static function tokenSet(AccessToken $token): array
    {
        $values = $token->getValues();

        return [
            'access_token' => $token->getToken(),
            'refresh_token' => $token->getRefreshToken(),
            'id_token' => $values['id_token'] ?? null,
            'token_type' => $values['token_type'] ?? 'Bearer',
            'scope' => $values['scope'] ?? null,
            // From this response's expires_in; never hardcode a lifetime.
            'expires_at' => $token->getExpires(),
        ];
    }

    /**
     * Whether an unknown-kid JWKS re-fetch is allowed now; records it if so.
     * The cooldown is kept in the PSR-16 cache when there is one (so it holds
     * across requests), and on this instance either way.
     */
    private function mayRefetchJwks(): bool
    {
        $now = time();
        if ($this->lastJwksRefetch !== null && $now - $this->lastJwksRefetch < self::JWKS_REFETCH_COOLDOWN) {
            return false;
        }
        $key = self::cacheKey($this->issuer(), 'jwks_refetch');
        if ($this->cache !== null) {
            $last = $this->cache->get($key);
            if (is_int($last) && $now - $last < self::JWKS_REFETCH_COOLDOWN) {
                return false;
            }
            $this->cache->set($key, $now, self::JWKS_REFETCH_COOLDOWN);
        }
        $this->lastJwksRefetch = $now;

        return true;
    }

    /** @return array<string, \Firebase\JWT\Key> */
    private function jwks(bool $refetch): array
    {
        if (!$refetch && $this->keys !== null) {
            return $this->keys;
        }
        $cacheKey = self::cacheKey($this->issuer(), 'jwks');
        $set = null;
        if (!$refetch && $this->cache !== null) {
            $cached = $this->cache->get($cacheKey);
            $set = is_string($cached) ? json_decode($cached, true) : null;
        }
        if (!is_array($set)) {
            $set = self::getJson($this->http, $this->metadata['jwks_uri']);
            if ($this->cache !== null) {
                $this->cache->set($cacheKey, json_encode($set), self::CACHE_TTL);
            }
        }
        // Accept only P-256 signing keys, and only for ES256.
        $usable = [];
        foreach (is_array($set['keys'] ?? null) ? $set['keys'] : [] as $jwk) {
            if (!is_array($jwk) || ($jwk['kty'] ?? null) !== 'EC' || ($jwk['crv'] ?? null) !== 'P-256') {
                continue;
            }
            if (isset($jwk['alg']) && $jwk['alg'] !== 'ES256') {
                continue;
            }
            if (isset($jwk['use']) && $jwk['use'] !== 'sig') {
                continue;
            }
            if (!isset($jwk['kid']) || !is_string($jwk['kid'])) {
                continue;
            }
            $jwk['alg'] = 'ES256';
            $usable[] = $jwk;
        }
        if ($usable === []) {
            throw new NobleIdException('server_error', 'the JWKS has no ES256 keys');
        }
        try {
            $this->keys = JWK::parseKeySet(['keys' => $usable], 'ES256');
        } catch (\Throwable $e) {
            throw new NobleIdException('server_error', 'the JWKS could not be parsed');
        }

        return $this->keys;
    }

    /** @return array<string, mixed> */
    private function bearerJson(string $url, #[\SensitiveParameter] string $accessToken): array
    {
        $res = $this->send('GET', $url, ['headers' => ['Authorization' => 'Bearer ' . $accessToken, 'Accept' => 'application/json']]);
        if ($res->getStatusCode() !== 200) {
            throw self::errorFrom($res);
        }
        $body = json_decode((string) $res->getBody(), true);
        if (!is_array($body) || array_is_list($body) && $body !== []) {
            throw new NobleIdException('server_error', 'expected a JSON object');
        }

        return $body;
    }

    /** @param array<string, mixed> $options */
    private function send(string $method, string $url, #[\SensitiveParameter] array $options): ResponseInterface
    {
        try {
            return $this->http->request($method, $url, $options + ['http_errors' => false, 'allow_redirects' => false]);
        } catch (GuzzleException $e) {
            throw new NobleIdException('server_error', 'request to the provider failed');
        }
    }

    private static function errorFrom(ResponseInterface $res): NobleIdException
    {
        $status = $res->getStatusCode();
        $body = json_decode((string) $res->getBody(), true);
        $error = is_array($body) && isset($body['error']) && is_string($body['error']) ? $body['error'] : null;
        if ($error === null && preg_match('/error="([^"]+)"/', $res->getHeaderLine('WWW-Authenticate'), $m)) {
            $error = $m[1];
        }
        $desc = is_array($body) && isset($body['error_description']) && is_string($body['error_description']) ? $body['error_description'] : '';
        $ra = $res->getHeaderLine('Retry-After');

        return new NobleIdException(
            self::safeCode($error ?? 'http_' . $status),
            self::safeText($desc),
            $status,
            ctype_digit($ra) ? (int) $ra : null,
        );
    }

    /** @return array<string, mixed> */
    private static function getJson(ClientInterface $http, string $url): array
    {
        try {
            $res = $http->request('GET', $url, ['headers' => ['Accept' => 'application/json'], 'http_errors' => false, 'allow_redirects' => false]);
        } catch (GuzzleException $e) {
            throw new NobleIdException('server_error', 'could not reach the provider');
        }
        if ($res->getStatusCode() !== 200) {
            throw self::errorFrom($res);
        }
        $data = json_decode((string) $res->getBody(), true);
        if (!is_array($data)) {
            throw new NobleIdException('server_error', 'the provider did not return JSON');
        }

        return $data;
    }

    /** Returns true for an http://localhost issuer (a local mock). */
    private static function checkIssuerUrl(string $issuer): bool
    {
        $u = parse_url($issuer);
        if (!is_array($u) || !isset($u['scheme'], $u['host']) || isset($u['query']) || isset($u['fragment']) || isset($u['user'])) {
            throw new NobleIdException('invalid_request', 'issuer must be an absolute URL without query or fragment');
        }
        if ($u['scheme'] === 'https') {
            return false;
        }
        if ($u['scheme'] === 'http' && in_array(strtolower($u['host']), self::LOCAL_HOSTS, true)) {
            return true;
        }
        throw new NobleIdException('invalid_request', 'the issuer must be https (http is allowed only for localhost)');
    }

    /** @param array<string, mixed> $m */
    private static function validateMetadata(array $m, string $issuer, bool $local): void
    {
        if (($m['issuer'] ?? null) !== $issuer) {
            throw new NobleIdException('invalid_issuer', 'discovery issuer does not match the configured issuer');
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $k) {
            if (!isset($m[$k]) || !is_string($m[$k])) {
                throw new NobleIdException('server_error', 'discovery document has no ' . $k);
            }
        }
        foreach (['authorization_endpoint', 'token_endpoint', 'jwks_uri', 'userinfo_endpoint', 'revocation_endpoint'] as $k) {
            if (!isset($m[$k])) {
                continue;
            }
            $u = is_string($m[$k]) ? parse_url($m[$k]) : false;
            $ok = is_array($u) && isset($u['scheme'], $u['host']) && (
                $u['scheme'] === 'https'
                || ($local && $u['scheme'] === 'http' && in_array(strtolower($u['host']), self::LOCAL_HOSTS, true))
            );
            if (!$ok) {
                throw new NobleIdException('server_error', $k . ' must be https');
            }
        }
        $algs = $m['id_token_signing_alg_values_supported'] ?? null;
        if (is_array($algs) && !in_array('ES256', $algs, true)) {
            throw new NobleIdException('server_error', 'the provider does not sign ID tokens with ES256');
        }
    }

    private static function cacheKey(string $issuer, string $what): string
    {
        return 'nobleid_' . hash('sha256', $issuer) . '_' . $what; // PSR-16 safe characters only
    }

    private static function random(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /** OAuth error codes are printable ASCII without quotes or backslashes (RFC 6749 5.2). */
    private static function safeCode(string $code): string
    {
        return preg_match('/^[\x20\x21\x23-\x5B\x5D-\x7E]{1,64}$/', $code) === 1 ? $code : 'server_error';
    }

    private static function safeText(string $text): string
    {
        $text = preg_replace('/[^\x20-\x7E]/', '', $text) ?? '';

        return strlen($text) > 300 ? substr($text, 0, 300) : $text;
    }
}
