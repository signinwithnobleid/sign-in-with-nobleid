# Logout

NobleID has **no end-session endpoint** and no back-channel logout. Do not
configure one in your library or plugin; leave that field empty.

Signing someone out of your app means:

1. Revoke the refresh token (this also ends the access tokens minted from it).
   If you have no refresh token, revoke the access token.
2. Clear your own session (server-side session and cookie, or in-memory
   tokens in a browser app).

```
POST https://id.nobleid.org/oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic …            (confidential clients)

token=nbrt_…&token_type_hint=refresh_token
```

Public clients send `client_id=…` in the body instead of authenticating.
The response is `200 {}` for any token, known or not (failed client
authentication and rate limits still get their usual errors).

## The person stays signed in to NobleID

Your logout does not sign them out of NobleID. The next "Sign in with
NobleID" may complete without a screen if they already approved your app.
To require a fresh NobleID sign-in, send `prompt=login` and check the ID
token's `auth_time`: reject it, and ask the person to sign in again, if it is
older than you accept. (`prompt=login` does not re-prompt someone who signed
in moments ago, and `max_age=0` does not force a sign-in yet.)

## When NobleID ends the session for you

The person can remove your app under NobleID Settings → Connected apps.
That revokes every token at once. You will see:

- `invalid_grant` on the next refresh: sign them out.
- `401 invalid_token` from userinfo or works: refresh, and if that fails, sign them out.

If your app is suspended, every token stops working.
