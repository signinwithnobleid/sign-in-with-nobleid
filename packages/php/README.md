# nobleid/signin (PHP)

Server-side helper for "Sign in with NobleID". A thin layer over two
well-used libraries, with NobleID's settings already chosen:

- [`league/oauth2-client`](https://github.com/thephpleague/oauth2-client)
  builds the authorization URL (PKCE S256, space-separated scopes) and runs
  the code and refresh grants.
- [`firebase/php-jwt`](https://github.com/firebase/php-jwt) verifies the ES256
  ID-token signature against the provider's JWKS.

The package adds what those libraries leave to you: discovery, state and
nonce, the RFC 9207 `iss` check on every callback, ID-token claim checks
(iss, aud, azp, exp, iat, nonce), userinfo, the works list and revocation.
It does no cryptography of its own.

PHP 8.3+ with `ext-openssl` and `ext-json`.

## Install

The package is **not yet published** on Packagist: install it from a
checkout of this repository as a `path` repository. Do not require
`nobleid/signin` from Packagist alone; anything published there under that
name is not ours.

```json
{
  "repositories": [{ "type": "path", "url": "../sign-in-with-nobleid/packages/php" }],
  "require": { "nobleid/signin": "^1.0" }
}
```

## Use

```php
use NobleId\SignIn\NobleIdClient;
use NobleId\SignIn\NobleIdException;

$nobleid = NobleIdClient::discover([
    'clientId'     => getenv('CLIENT_ID'),      // nbcl_...
    'clientSecret' => getenv('CLIENT_SECRET'),  // nbcs_..., never in source control
    'redirectUri'  => 'https://app.example/callback',
    // 'issuer'    => 'https://id.nobleid.org',  // the default
    // 'cache'     => $psr16Cache,               // caches discovery + JWKS
]);

// GET /login
[$url, $transaction] = $nobleid->startSignIn('openid profile email orcid affiliations works offline_access');
$_SESSION['nobleid_tx'] = $transaction;          // server-side only
header('Location: ' . $url, true, 303);

// GET /callback
$tx = $_SESSION['nobleid_tx'] ?? null;
unset($_SESSION['nobleid_tx']);                  // single use
try {
    $r = $nobleid->finishSignIn($_GET, $tx);     // ['tokens', 'claims', 'scope']
    $info = $nobleid->userinfo($r['tokens']['access_token'], $r['claims']['sub']);
    session_regenerate_id(true);
    $_SESSION['user'] = array_merge($r['claims'], $info);
    $_SESSION['tokens'] = $r['tokens'];
    $_SESSION['scope'] = $r['scope'];            // what the user actually granted
} catch (NobleIdException $e) {
    // $e->error is the OAuth error code, e.g. access_denied, invalid_state
}
```

Key accounts on `sub`, never on email. Link by email only when
`email_verified` is true.

## API

| Method | What it does |
|---|---|
| `NobleIdClient::discover(array $options)` | Fetches `{issuer}/.well-known/openid-configuration` and checks that its `issuer` matches exactly and every endpoint is https. `http` is accepted only for `localhost` / `127.0.0.1` (a local mock). |
| `startSignIn(string $scope, array $extra = [])` | Returns `[url, transaction]`. The transaction holds `state`, `nonce`, `code_verifier`, `created_at`. `$extra` may set `prompt`, `login_hint`, `max_age`. |
| `finishSignIn(array $query, ?array $transaction)` | Checks, in order: a sign-in is in progress; `state` matches (`hash_equals`); `iss` equals the issuer (missing `iss` is rejected); then any `error`; a `code` is present; the flow is at most 10 minutes old. Then exchanges the code with the PKCE verifier and verifies the ID token (ES256 only, JWKS, iss, aud, exp, nonce). Returns `tokens`, `claims` and the granted `scope`. |
| `userinfo(string $accessToken, string $expectedSub)` | GET userinfo with a Bearer token. Returns an array that includes the userinfo-only claims (`affiliations`, `research_interests`, `works_count`, `verified_authorship_count`). |
| `works(string $accessToken, int $limit = 50, int $offset = 0)` | The user's registered works (`works` scope). `limit` 1..100. |
| `refresh(string $refreshToken, ?string $expectedSub = null)` | Refresh-token grant. Returns a new token set, including the **rotated** refresh token. |
| `revoke(string $token, ?string $hint = null)` | RFC 7009 revocation. |
| `verifyIdToken(string $jwt, ?string $nonce)` | The ID-token check on its own, for ID tokens your server got from NobleID's token endpoint. Not for verifying tokens a browser or app sends you: an ID token proves nothing about who is presenting it. |

`tokens` carries `access_token`, `refresh_token` (only with `offline_access`),
`id_token`, `token_type`, `scope` and `expires_at`, computed from the
response's `expires_in`. Do not hardcode token lifetimes.

Fill your app's profile: `Profile::fromClaims($r['claims'], $info)` returns a
plain array (`name`, `given_name`, `picture`, `orcid`, `affiliation`,
`affiliations`, …), every key present and `null`, `[]` or `false` when not
shared. `orcid` is set only when proven through ORCID. It throws
`NobleIdException` `invalid_token` if userinfo is for another `sub`. No
dependencies; its tests run with `php tests/ProfileTest.php`. Fill only empty
fields with it: [docs/profile-data.md](../../docs/profile-data.md).

## Things to get right

- **Refresh tokens rotate.** Store the new one every time. Presenting a used
  refresh token again ends the user's whole session, so never run two
  refreshes of the same token at once. Serialise them per user session; PHP's
  default file session handler already locks the session for the length of a
  request. On `invalid_grant`, sign the user out.
- **Refresh-issued ID tokens** have no `nonce`, `auth_time` or `amr`.
  `refresh()` verifies them without a nonce and, given `$expectedSub`, checks
  the user did not change.
- **Sign-out:** NobleID has no end-session endpoint. Revoke the refresh token
  (that also ends its access tokens), revoke the access token, then clear
  your own session.
- **Scopes can be unticked** by the user, except `openid`. Read `scope` from
  the result, not from your request.
- **Rate limits:** a `NobleIdException` with `error` `slow_down` and `status`
  429 may carry `retryAfter` (seconds). Back off.
- **Caching:** without a `cache`, every new client fetches the discovery
  document, and the JWKS on first use. Pass any PSR-16 cache in production.
  An ID token with an unknown `kid` makes the client fetch the JWKS again,
  at most once every 30 seconds (tracked in the cache when there is one).
- **Your own Guzzle client:** if you pass `httpClient`, configure it like the
  default: `'allow_redirects' => false` (a redirect must never carry a token
  or client secret elsewhere), `'http_errors' => false` and a `timeout`.
- **Errors:** `NobleIdException::$error` is the OAuth error code.
  Messages never contain tokens, codes or secrets, and token parameters are
  marked `#[\SensitiveParameter]` so they stay out of stack traces.

## Library settings, if you use the libraries directly

| Setting | Why |
|---|---|
| `GenericProvider` `'scopeSeparator' => ' '` | league's default is `,`. |
| `GenericProvider` `'pkceMethod' => 'S256'` | PKCE is off by default; never use `plain`. |
| `'approval_prompt' => null` in `getAuthorizationUrl()` | league adds `approval_prompt=auto` otherwise. |
| `client_secret_basic` with form-urlencoded id and secret | league's `HttpBasicAuthOptionProvider` skips the urlencoding step; see `ClientSecretBasicOptionProvider`. |
| `JWK::parseKeySet($jwks, 'ES256')`, then reject any `alg` other than ES256 | ID tokens are ES256 only. |
| Check `iss` on the callback yourself | Neither library implements RFC 9207. |
| Check `iss`, `aud`, `nonce` claims yourself | php-jwt checks the signature, `exp`, `nbf` and `iat` only, and does not require `exp`. |

## License

Apache-2.0
