# Logout

Signing someone out of your app means:

1. Revoke the refresh token (this also ends the access tokens minted from it).
   If you have no refresh token, revoke the access token.
2. Clear your own session (server-side session and cookie, or in-memory
   tokens in a browser app).
3. Optionally, sign them out of NobleID too, with the end-session endpoint
   (below).

```
POST https://id.nobleid.org/oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic …            (confidential clients)

token=nbrt_…&token_type_hint=refresh_token
```

Public clients send `client_id=…` in the body instead of authenticating.
The response is `200 {}` for any token, known or not (failed client
authentication and rate limits still get their usual errors).

## Signing out of NobleID too (RP-Initiated Logout)

Discovery publishes `end_session_endpoint`:
`https://www.nobleid.org/oauth/logout`. Like the authorization endpoint, it
is a page on the www host, not on the issuer. It follows
[OpenID Connect RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html).

After steps 1 and 2, send the browser there, with a GET or an HTML form
POST. A form POST keeps the ID token out of browser history and server logs.

```
https://www.nobleid.org/oauth/logout
  ?id_token_hint=<the ID token from sign-in>
  &post_logout_redirect_uri=https://app.example.org/signed-out
  &state=<random, checked when the browser comes back>
```

- `id_token_hint`: the ID token you received at sign-in. It may have
  expired. NobleID checks that it signed it and that it was issued to your
  app. You may send `client_id` as well; it must match. Without an ID token,
  send `client_id`: a return address with neither is refused.
- `post_logout_redirect_uri`: where to send the person afterwards. It must
  **exactly** match one of your app's *sign-out return URLs* (Dashboard →
  OAuth apps), query string included. Unlike sign-in redirect URIs, a
  `localhost` port must match too. Your sign-in redirect URIs do not count.
  An unregistered address is refused on NobleID and the person is sent
  nowhere. Platforms that build the address per user (WordPress adds the
  user's language) cannot use it; see [troubleshooting](troubleshooting.md).
- `state`: returned unchanged on the redirect.

NobleID always asks the person before ending their NobleID session ("Sign
out" or "Stay signed in"); either way they are sent back to your return URL.
Someone who is not signed in to NobleID is sent back at once.

What it does not do: there is no front-channel or back-channel logout.
Other apps the person signed in to with NobleID are not told and stay signed
in.

The [local mock](../mock-oidc/README.md) serves the same endpoint, with the
same checks, so you can test your sign-out without an account. It does not
ask the person first.

## Without the end-session endpoint

The person stays signed in to NobleID. The next "Sign in with NobleID" may
complete without a screen if they already approved your app. To require a
fresh NobleID sign-in, send `prompt=login` and check the ID token's
`auth_time`: reject it, and ask the person to sign in again, if it is older
than you accept. (`prompt=login` does not re-prompt someone who signed in
moments ago, and `max_age=0` does not force a sign-in yet.)

## When NobleID ends the session for you

The person can remove your app under NobleID Settings → Connected apps.
That revokes every token at once. You will see:

- `invalid_grant` on the next refresh: sign them out.
- `401 invalid_token` from userinfo or works: refresh, and if that fails, sign them out.

If your app is suspended, every token stops working.
