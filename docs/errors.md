# Errors

## Errors shown on NobleID (never redirected)

If the request names an unknown `client_id`, or a `redirect_uri` that is not
registered for it exactly, NobleID shows the error itself and does **not**
redirect. Nothing reaches your app. Check the client id and the exact
redirect URI (scheme, host, port, path, query) in your app settings.

A PAR `request_uri` that is unknown, expired, already used, or belongs to
another client (`invalid_request_uri`) is also shown on NobleID, not
redirected: without a valid request object NobleID has no checked redirect
URI to send it to. Push the request again and start a new sign-in.

## Errors on your redirect URI

Once the client and redirect URI match, errors come back to you as query
parameters:

```
https://app.example/callback?error=access_denied&error_description=…&state=…&iss=https%3A%2F%2Fid.nobleid.org
```

Handle the callback in this order:

1. A sign-in was started in this session (and use its state only once).
2. `state` matches (constant-time comparison).
3. `iss` equals `https://id.nobleid.org` (RFC 9207). A missing `iss` is a failure.
4. Only now look at `error`.
5. Then `code`, the flow's age, and the code exchange.

An `error` that arrives with the wrong `state` or `iss` is not from NobleID
for this sign-in: treat it as a forged response, not as the error it claims.

| `error` | Meaning | What to do |
|---|---|---|
| `access_denied` | The person declined. | Show a calm message and a way to try again. |
| `login_required` | `prompt=none` and the person is not signed in to NobleID. | Retry without `prompt=none`. |
| `consent_required` | `prompt=none` and a consent screen is needed. | Retry without `prompt=none`. |
| `interaction_required` | `prompt=none` and the person must first add something to their NobleID account (a real name). | Retry without `prompt=none`; NobleID asks them for it. |
| `invalid_scope` | Unknown scope, a scope your app is not registered for, or `openid` missing. | Fix the request. |
| `invalid_request` | Malformed request: PKCE missing for a public client, `plain` PKCE, unsupported `response_mode`, `prompt=none` combined with `login` or `consent`, bad `max_age`. | Fix the request. Send each parameter once (if one is repeated, only the first is used). |
| `request_not_supported` | A `request` object was sent. | Send plain parameters, or use PAR. |
| `unsupported_response_type` | Anything but `code`. | Use the code flow. |

## Token endpoint errors

| Status | `error` | Typical cause |
|---|---|---|
| 400 | `invalid_request` | Body not form-urlencoded, repeated parameter, missing parameter, or Basic and body client credentials in one request. |
| 401 | `invalid_client` | Wrong secret, unknown client, public client sending a secret, malformed Basic credentials. For a wrong id or secret the body is `{"error":"invalid_client","error_description":"Client authentication failed"}`. |
| 400 | `invalid_grant` | Code expired, used, or issued to another client; `redirect_uri` differs; PKCE verifier wrong or unexpected; refresh token used, expired or revoked. |
| 400 | `invalid_scope` | Refresh asked for more than was granted. |
| 400 | `unsupported_grant_type` | Only `authorization_code` and `refresh_token` exist. |
| 429 | `slow_down` | Rate limited. See below. |

## Userinfo and works errors

| Status | Body | `WWW-Authenticate` | Cause |
|---|---|---|---|
| 401 | (empty) | `Bearer realm="nobleid"` | No token sent. |
| 401 | `{"error":"invalid_token", …}` | `Bearer realm="nobleid", error="invalid_token"` | Expired, revoked or unknown token. Refresh, or sign the person in again. |
| 403 | `{"error":"insufficient_scope", …}` | with `error="insufficient_scope"` | userinfo without `openid`; works without `works`. |
| 400 | `{"error":"invalid_request", …}` | | Token sent twice (header and body), or a POST body that is not form-urlencoded. |
| 429 | `{"error":"slow_down", …}` | | Rate limited. |

Error bodies also carry an `error_description` for developers. A token in
the query string is ignored, so such a request gets the bare `401`.

## Rate limits (429 `slow_down`)

Protocol endpoints are rate limited. The values are not published and may
change.

- On `429` with `{"error":"slow_down"}`, stop and retry later.
- If `Retry-After` is present, wait at least that long. Otherwise back off
  exponentially with jitter (for example 1 s, 2 s, 4 s … capped).
- Never retry a token exchange with the same authorization code in a loop:
  codes are single use.
- Cache discovery and the JWKS (respect `Cache-Control`); refresh only when
  needed.

## App suspended

NobleID can suspend an app. All its tokens stop working.
