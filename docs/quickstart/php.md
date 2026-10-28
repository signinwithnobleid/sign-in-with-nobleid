# PHP

Helper: [`packages/php`](../../packages/php/README.md) (`nobleid/signin`, PHP
8.3+, not yet on Packagist) over `league/oauth2-client` and
`firebase/php-jwt`. Example: [`examples/php-plain`](../../examples/php-plain/README.md).

Using league/oauth2-client directly (`GenericProvider`):

- `'scopeSeparator' => ' '` (the default is a comma).
- `'pkceMethod' => 'S256'`; keep `getPkceCode()` in the session and call
  `setPkceCode()` before the exchange.
- Pass `'approval_prompt' => null` to drop the `approval_prompt=auto` it adds.
- League's HTTP Basic option provider does not form-urlencode the id and
  secret; use client_secret_post (league's default) or a provider that does.
- league does not handle ID tokens: verify with `firebase/php-jwt`
  (`JWK::parseKeySet` with ES256 keys only), then check `iss`, `aud`, `nonce`
  yourself; php-jwt checks only the signature and the time claims.
- Check the `iss` response parameter yourself.

`jumbojett/openid-connect-php` (1.0.2) cannot verify ES256 ID tokens; do not
use it with NobleID.
