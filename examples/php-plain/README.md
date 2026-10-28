# Sign in with NobleID: plain PHP

A small PHP app for the built-in web server, using the
[`nobleid/signin`](../../packages/php) package (league/oauth2-client +
firebase/php-jwt). Confidential client: the secret and the tokens stay on the
server; the browser only gets a PHP session cookie.

PHP 8.3+ with `openssl`, `json` and `session` (`curl` recommended), plus Composer.

## Run

```sh
cp .env.example .env              # fill in your client id and secret
composer install --no-dev         # or: php composer.phar install --no-dev
set -a; . ./.env; set +a
php -S localhost:3000 -t public public/index.php
```

Open http://localhost:3000. The package comes from `../../packages/php`
through a Composer `path` repository, so run the commands from this directory
inside the kit.

`php -S` is for development only. In production, serve `public/` from a real
web server with PHP-FPM, over https.

## Routes

| Route | What it does |
|---|---|
| `GET /` | Signed out: a sign-in link. Signed in: the ID-token claims merged with userinfo. |
| `GET /login` | Creates state, nonce and a PKCE S256 verifier, keeps them in the session, redirects to NobleID. |
| `GET /callback` | Checks state, then `iss`, then any `error`; exchanges the code; verifies the ID token; calls userinfo; starts a new session id. |
| `GET /works` | The user's registered works (`works` scope). |
| `POST /refresh` | Refresh-token grant; stores the rotated refresh token. |
| `POST /logout` | Revokes the refresh and access tokens, then destroys the session. |

## What it does for you

- Session cookie `HttpOnly`, `SameSite=Lax`, `Secure` on https; strict session
  ids; `session_regenerate_id(true)` after sign-in.
- POST routes need the hidden CSRF token and, when the browser sends one, a
  same-origin `Origin` header.
- Everything rendered goes through `htmlspecialchars`.
- Tokens, codes and secrets are never logged or shown.
- Refreshes for one user cannot overlap: PHP's file session handler locks the
  session for each request. If you use another session handler, make sure it
  locks, or serialise refreshes yourself. A used refresh token presented
  again ends the user's session.
- Discovery runs only on routes that talk to NobleID. Pass a PSR-16 `cache`
  to `NobleIdClient::discover()` in production.

## Test

From the kit root, with `php` and `composer` on `PATH`:

```sh
node test/run-example.mjs php-plain
```

This runs `composer install --no-dev`, starts the app with `php -S` against
the local mock provider, and plays the sign-in scenarios in
[`test/README.md`](../../test/README.md).
